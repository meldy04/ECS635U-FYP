"""
Online Booking System
Peripheral System (Internet-facing entry point)

Sends passenger bookings and PII to DCS via REST API.
Provides passenger-facing booking and management interface.

Intentional Vulnerabilities:
- SQL injection on booking lookup
- IDOR on booking management (sequential IDs exposed)
- Information disclosure in error messages
- No input validation on passenger data
- No CSRF protection
- Weak session management
- PII stored in plaintext (SQLite)
"""

import os
import json
import sqlite3
import random
import string
import requests
from datetime import datetime

from flask import Flask, request, jsonify, g, render_template_string, session, redirect

app = Flask(__name__)
app.secret_key = 'booking-secret-not-very-secret'  # VULNERABILITY: weak secret key

DCS_API_URL = os.environ.get('DCS_API_URL', 'http://dcs:5000')
DB_PATH = os.environ.get('DB_PATH', '/app/booking.db')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reference TEXT UNIQUE NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL,
        passport_number TEXT NOT NULL,
        date_of_birth TEXT,
        nationality TEXT,
        flight_number TEXT NOT NULL,
        travel_class TEXT DEFAULT 'economy',
        num_bags INTEGER DEFAULT 0,
        total_price REAL,
        payment_status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    bookings = [
        ('ABCD1234', 'James', 'Wilson', 'j.wilson@email.com', 'GB123456789',
         '1985-03-14', 'British', 'BA0117', 'business', 1, 1249.99, 'paid'),
        ('EFGH5678', 'Sarah', 'Chen', 's.chen@email.com', 'GB987654321',
         '1990-07-22', 'British', 'BA0117', 'economy', 2, 459.99, 'paid'),
        ('IJKL9012', 'Ahmed', 'Hassan', 'a.hassan@email.com', 'GB456789123',
         '1978-11-05', 'British', 'BA0303', 'economy', 1, 189.50, 'paid'),
        ('MNOP3456', 'Maria', 'Garcia', 'm.garcia@email.com', 'ES112233445',
         '1995-01-30', 'Spanish', 'VS0401', 'economy', 1, 589.00, 'paid'),
        ('QRST7890', 'Thomas', 'Mueller', 't.mueller@email.com', 'DE998877665',
         '1982-09-18', 'German', 'EK0007', 'business', 2, 2199.00, 'paid'),
    ]
    for b in bookings:
        try:
            conn.execute(
                "INSERT INTO bookings (reference, first_name, last_name, email, passport_number, date_of_birth, nationality, flight_number, travel_class, num_bags, total_price, payment_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                b
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db:
        db.close()


def generate_reference():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))


# ============================================================
# Templates
# ============================================================

HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>SkyBook - Airport Booking System</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #f5f7fa; font-family: 'Segoe UI', Arial, sans-serif; }
    .nav { background: #2c3e50; padding: 15px 30px; color: #fff; display: flex; justify-content: space-between; align-items: center; }
    .nav h1 { font-size: 22px; } .nav a { color: #3498db; text-decoration: none; margin-left: 20px; }
    .container { max-width: 900px; margin: 30px auto; padding: 0 20px; }
    .card { background: #fff; border-radius: 8px; padding: 30px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
    h2 { color: #2c3e50; margin-bottom: 15px; }
    input, select { width: 100%; padding: 10px; margin: 6px 0 14px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
    label { font-weight: bold; color: #555; font-size: 14px; }
    button { background: #3498db; color: #fff; padding: 12px 24px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
    button:hover { background: #2980b9; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
    .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 4px; margin: 10px 0; }
    .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; margin: 10px 0; }
    .flight-list { list-style: none; }
    .flight-list li { padding: 10px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
</style>
</head>
<body>
    <div class="nav">
        <h1>SkyBook</h1>
        <div><a href="/">Home</a><a href="/manage">Manage Booking</a><a href="/flights">Flights</a></div>
    </div>
    <div class="container">
        {% if message %}<div class="success">{{ message }}</div>{% endif %}
        {% if error %}<div class="error">{{ error }}</div>{% endif %}

        <div class="card">
            <h2>Book a Flight</h2>
            <form method="POST" action="/book">
                <div class="grid">
                    <div><label>First Name</label><input type="text" name="first_name" required></div>
                    <div><label>Last Name</label><input type="text" name="last_name" required></div>
                    <div><label>Email</label><input type="email" name="email" required></div>
                    <div><label>Passport Number</label><input type="text" name="passport_number" required></div>
                    <div><label>Date of Birth</label><input type="date" name="date_of_birth" required></div>
                    <div><label>Nationality</label><input type="text" name="nationality" required></div>
                </div>
                <label>Flight</label>
                <select name="flight_number">
                    <option value="BA0117">BA0117 - LHR → JFK (British Airways)</option>
                    <option value="BA0303">BA0303 - LHR → CDG (British Airways)</option>
                    <option value="VS0401">VS0401 - LHR → LAX (Virgin Atlantic)</option>
                    <option value="EK0007">EK0007 - LHR → DXB (Emirates)</option>
                    <option value="LH0901">LH0901 - LHR → FRA (Lufthansa)</option>
                    <option value="AF1081">AF1081 - LHR → CDG (Air France)</option>
                    <option value="UA0919">UA0919 - LHR → EWR (United Airlines)</option>
                    <option value="BA0853">BA0853 - LHR → BER (British Airways)</option>
                </select>
                <div class="grid">
                    <div><label>Class</label>
                        <select name="travel_class">
                            <option value="economy">Economy</option>
                            <option value="business">Business</option>
                            <option value="first">First</option>
                        </select>
                    </div>
                    <div><label>Number of Bags</label><input type="number" name="num_bags" value="1" min="0" max="5"></div>
                </div>
                <button type="submit">Book Flight</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

MANAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Manage Booking - SkyBook</title>
<style>
    body { background: #f5f7fa; font-family: 'Segoe UI', Arial, sans-serif; }
    .nav { background: #2c3e50; padding: 15px 30px; color: #fff; display: flex; justify-content: space-between; }
    .nav h1 { font-size: 22px; } .nav a { color: #3498db; text-decoration: none; margin-left: 20px; }
    .container { max-width: 700px; margin: 30px auto; padding: 0 20px; }
    .card { background: #fff; border-radius: 8px; padding: 30px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
    h2 { color: #2c3e50; margin-bottom: 15px; }
    input { width: 100%; padding: 10px; margin: 6px 0 14px; border: 1px solid #ddd; border-radius: 4px; }
    button { background: #3498db; color: #fff; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
    .detail { padding: 8px 0; border-bottom: 1px solid #eee; }
    .detail strong { display: inline-block; width: 160px; color: #555; }
    .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; }
</style>
</head>
<body>
    <div class="nav"><h1>SkyBook</h1><div><a href="/">Home</a><a href="/manage">Manage Booking</a></div></div>
    <div class="container">
        <div class="card">
            <h2>Manage Your Booking</h2>
            <form method="GET" action="/manage">
                <input type="text" name="ref" placeholder="Enter booking reference (e.g. ABCD1234)" value="{{ ref or '' }}">
                <button type="submit">Look Up</button>
            </form>
        </div>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        {% if booking %}
        <div class="card">
            <h2>Booking {{ booking.reference }}</h2>
            <div class="detail"><strong>Passenger:</strong> {{ booking.first_name }} {{ booking.last_name }}</div>
            <div class="detail"><strong>Email:</strong> {{ booking.email }}</div>
            <div class="detail"><strong>Passport:</strong> {{ booking.passport_number }}</div>
            <div class="detail"><strong>Flight:</strong> {{ booking.flight_number }}</div>
            <div class="detail"><strong>Class:</strong> {{ booking.travel_class }}</div>
            <div class="detail"><strong>Bags:</strong> {{ booking.num_bags }}</div>
            <div class="detail"><strong>Total Price:</strong> £{{ "%.2f"|format(booking.total_price or 0) }}</div>
            <div class="detail"><strong>Payment:</strong> {{ booking.payment_status }}</div>
            <div class="detail"><strong>Booked:</strong> {{ booking.created_at }}</div>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""


# ============================================================
# Routes
# ============================================================

@app.route('/')
def home():
    return render_template_string(HOME_TEMPLATE, message=request.args.get('message'), error=request.args.get('error'))


@app.route('/book', methods=['POST'])
def book():
    """
    Create a new booking.

    VULNERABILITY: No input validation or sanitisation on passenger data.
    VULNERABILITY: No CSRF token.
    """
    ref = generate_reference()
    data = request.form

    # Store locally
    db = get_db()
    price = {'economy': 459.99, 'business': 1249.99, 'first': 2499.99}.get(
        data.get('travel_class', 'economy'), 459.99)

    try:
        db.execute("""
            INSERT INTO bookings (reference, first_name, last_name, email, passport_number,
                                 date_of_birth, nationality, flight_number, travel_class, num_bags,
                                 total_price, payment_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'paid')
        """, (ref, data['first_name'], data['last_name'], data['email'],
              data['passport_number'], data.get('date_of_birth', ''),
              data.get('nationality', ''), data['flight_number'],
              data.get('travel_class', 'economy'), int(data.get('num_bags', 1)), price))
        db.commit()
    except Exception as e:
        # VULNERABILITY: error message reveals database details
        return redirect(f"/?error=Booking failed: {str(e)}")

    try:
        passenger_resp = requests.post(f"{DCS_API_URL}/api/passengers", json={
            'first_name': data['first_name'],
            'last_name': data['last_name'],
            'email': data['email'],
            'passport_number': data['passport_number'],
            'date_of_birth': data.get('date_of_birth', ''),
            'nationality': data.get('nationality', '')
        }, timeout=5)
    except Exception:
        pass

    return redirect(f"/?message=Booking confirmed! Reference: {ref}")


@app.route('/manage')
def manage():
    """
    Look up booking by reference.

    VULNERABILITY: SQL injection on 'ref' parameter.
    """
    ref = request.args.get('ref', '')
    if not ref:
        return render_template_string(MANAGE_TEMPLATE, booking=None, ref=None, error=None)

    db = get_db()
    sql = f"SELECT * FROM bookings WHERE reference = '{ref}'"
    try:
        booking = db.execute(sql).fetchone()
    except Exception as e:
        # VULNERABILITY: error reveals database structure
        return render_template_string(MANAGE_TEMPLATE, booking=None, ref=ref,
                                      error=f"Lookup failed: {str(e)}")

    if not booking:
        return render_template_string(MANAGE_TEMPLATE, booking=None, ref=ref,
                                      error="Booking not found")

    return render_template_string(MANAGE_TEMPLATE, booking=booking, ref=ref, error=None)


@app.route('/api/bookings/<int:booking_id>')
def api_booking(booking_id):
    """
    API endpoint to retrieve booking by numeric ID.

    VULNERABILITY: IDOR.
    No authentication required.
    """
    db = get_db()
    booking = db.execute(
        "SELECT * FROM bookings WHERE id = ?", (booking_id,)).fetchone()
    if not booking:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(booking))


@app.route('/flights')
def flights():
    """Proxy to DCS flight list for display."""
    try:
        resp = requests.get(f"{DCS_API_URL}/api/flights", timeout=5)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({'error': f'DCS unavailable: {str(e)}'}), 503


@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'system': 'Online Booking System', 'version': '3.2.1'})


# ============================================================
# Start
# ============================================================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5002, debug=True)
