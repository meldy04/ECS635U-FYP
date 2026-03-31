"""
Flight Information Display System (FIDS)
Peripheral System

Subscribes to DCS flight updates via Redis pub/sub.
Serves a public flight display and an admin panel.

Intentional Vulnerabilities:
- SQL injection on flight search
- Default admin credentials (admin/admin)
- No password complexity or expiry
- Information disclosure in admin panel
- XSS via flight status display (stored XSS if attacker modifies flight data)
"""

import os
import json
import sqlite3
import threading
from datetime import datetime

import redis
from flask import Flask, request, jsonify, g, render_template_string

app = Flask(__name__)

REDIS_HOST = os.environ.get('REDIS_HOST', 'redis')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
DCS_API_URL = os.environ.get('DCS_API_URL', 'http://dcs:5000')
DB_PATH = os.environ.get('DB_PATH', '/app/fids.db')

# Default admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'


def init_db():
    """Initialise FIDS local cache database"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS flights (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flight_number TEXT UNIQUE NOT NULL,
        airline TEXT,
        origin TEXT,
        destination TEXT,
        scheduled_departure TEXT,
        estimated_departure TEXT,
        gate TEXT,
        status TEXT DEFAULT 'scheduled',
        aircraft_type TEXT,
        last_updated TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        last_login TEXT
    )''')
    # VULNERABILITY: plaintext password storage, default credentials
    conn.execute("INSERT OR IGNORE INTO admin_users (username, password) VALUES (?, ?)",
                 (ADMIN_USERNAME, ADMIN_PASSWORD))
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


# ============================================================
# Redis subscriber - listens for DCS flight updates
# ============================================================

def redis_subscriber():
    """Background thread subscribing to DCS flight updates"""
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                        decode_responses=True)
        pubsub = r.pubsub()
        pubsub.subscribe('fids:updates')
        print("[FIDS] Subscribed to fids:updates channel")

        for message in pubsub.listen():
            if message['type'] == 'message':
                try:
                    payload = json.loads(message['data'])
                    flight = payload.get('data', {})
                    update_local_cache(flight)
                    print(
                        f"[FIDS] Updated flight {flight.get('flight_number', '?')}")
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"[FIDS] Error processing message: {e}")
    except Exception as e:
        print(f"[FIDS] Redis subscriber error: {e}")


def update_local_cache(flight_data):
    """Update local SQLite cache with flight data from DCS"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO flights (flight_number, airline, origin, destination,
                           scheduled_departure, estimated_departure, gate, status,
                           aircraft_type, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(flight_number) DO UPDATE SET
            estimated_departure = excluded.estimated_departure,
            gate = excluded.gate,
            status = excluded.status,
            last_updated = excluded.last_updated
    """, (
        flight_data.get('flight_number'),
        flight_data.get('airline'),
        flight_data.get('origin'),
        flight_data.get('destination'),
        flight_data.get('scheduled_departure'),
        flight_data.get('estimated_departure'),
        flight_data.get('gate'),
        flight_data.get('status'),
        flight_data.get('aircraft_type'),
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()


def seed_from_dcs():
    """Pull initial flight data from DCS on startup"""
    import requests
    try:
        resp = requests.get(f"{DCS_API_URL}/api/flights", timeout=10)
        if resp.status_code == 200:
            flights = resp.json().get('flights', [])
            for f in flights:
                update_local_cache(f)
            print(f"[FIDS] Seeded {len(flights)} flights from DCS")
    except Exception as e:
        print(f"[FIDS] Could not seed from DCS: {e}")


# ============================================================
# Display templates
# ============================================================

DISPLAY_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Flight Information Display</title>
    <meta http-equiv="refresh" content="30">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0e17; color: #e0e0e0; font-family: 'Courier New', monospace; }
        .header { background: #1a237e; padding: 20px; text-align: center; }
        .header h1 { color: #ffeb3b; font-size: 28px; letter-spacing: 4px; }
        .header p { color: #90caf9; font-size: 14px; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 2px; }
        th { background: #1a237e; color: #ffeb3b; padding: 12px 15px; text-align: left;
             font-size: 14px; letter-spacing: 2px; text-transform: uppercase; }
        td { padding: 10px 15px; border-bottom: 1px solid #1a2332; font-size: 16px; }
        tr:nth-child(even) { background: #0d1421; }
        tr:hover { background: #162744; }
        .status-scheduled { color: #4caf50; }
        .status-boarding { color: #ffeb3b; font-weight: bold; animation: blink 1s infinite; }
        .status-delayed { color: #ff5722; font-weight: bold; }
        .status-departed { color: #9e9e9e; }
        .status-cancelled { color: #f44336; text-decoration: line-through; }
        @keyframes blink { 50% { opacity: 0.5; } }
        .footer { text-align: center; padding: 15px; color: #555; font-size: 11px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>DEPARTURES</h1>
        <p>London Heathrow Airport &mdash; Terminal 5</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Flight</th>
                <th>Airline</th>
                <th>Destination</th>
                <th>Scheduled</th>
                <th>Estimated</th>
                <th>Gate</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {% for f in flights %}
            <tr>
                <td>{{ f.flight_number }}</td>
                <td>{{ f.airline }}</td>
                <td>{{ f.destination }}</td>
                <td>{{ f.scheduled_departure[:16] if f.scheduled_departure else '-' }}</td>
                <td>{{ f.estimated_departure[:16] if f.estimated_departure else '-' }}</td>
                <td>{{ f.gate or '-' }}</td>
                <!-- VULNERABILITY: XSS - status rendered without escaping via safe filter -->
                <td class="status-{{ f.status }}">{{ f.status|safe }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <div class="footer">
        Last updated: {{ now }} | FIDS v1.3.2 | &copy; Airport Systems Ltd
    </div>
</body>
</html>
"""

ADMIN_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>FIDS Admin</title>
<style>
    body { background: #1a1a2e; color: #eee; font-family: Arial, sans-serif;
           display: flex; justify-content: center; align-items: center; height: 100vh; }
    .login-box { background: #16213e; padding: 40px; border-radius: 8px; width: 350px; }
    h2 { text-align: center; margin-bottom: 20px; color: #e94560; }
    input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #333;
            border-radius: 4px; background: #0f3460; color: #fff; }
    button { width: 100%; padding: 12px; background: #e94560; color: #fff; border: none;
             border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 10px; }
    .error { color: #ff5722; text-align: center; margin-top: 10px; }
</style>
</head>
<body>
    <div class="login-box">
        <h2>FIDS Administration</h2>
        <form method="POST" action="/admin/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
    </div>
</body>
</html>
"""

ADMIN_PANEL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>FIDS Admin Panel</title>
<style>
    body { background: #1a1a2e; color: #eee; font-family: Arial, sans-serif; padding: 20px; }
    h1 { color: #e94560; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th { background: #16213e; padding: 10px; text-align: left; color: #e94560; }
    td { padding: 8px 10px; border-bottom: 1px solid #333; }
    .info { background: #0f3460; padding: 15px; border-radius: 4px; margin: 10px 0; }
    a { color: #e94560; }
    input, select { padding: 6px; margin: 4px; background: #0f3460; color: #fff; border: 1px solid #333; }
    button { padding: 8px 16px; background: #e94560; color: #fff; border: none; cursor: pointer; }
</style>
</head>
<body>
    <h1>FIDS Administration Panel</h1>
    <!-- VULNERABILITY: Information disclosure -->
    <div class="info">
        <strong>System:</strong> FIDS v1.3.2 | <strong>Database:</strong> SQLite {{ db_path }} |
        <strong>DCS Endpoint:</strong> {{ dcs_url }} | <strong>Redis:</strong> {{ redis_host }}:{{ redis_port }} |
        <strong>Flights cached:</strong> {{ flight_count }}
    </div>

    <h2>Flight Search</h2>
    <form method="GET" action="/admin/search">
        <input type="text" name="q" placeholder="Search flight number..." value="{{ query or '' }}">
        <button type="submit">Search</button>
    </form>

    <h2>All Flights</h2>
    <table>
        <tr><th>Flight</th><th>Airline</th><th>Dest</th><th>Gate</th><th>Status</th><th>Updated</th></tr>
        {% for f in flights %}
        <tr>
            <td>{{ f.flight_number }}</td>
            <td>{{ f.airline }}</td>
            <td>{{ f.destination }}</td>
            <td>{{ f.gate or '-' }}</td>
            <td>{{ f.status }}</td>
            <td>{{ f.last_updated or '-' }}</td>
        </tr>
        {% endfor %}
    </table>
    <br><a href="/admin/login">Logout</a>
</body>
</html>
"""


# ============================================================
# Routes
# ============================================================

@app.route('/')
def display():
    """Public departure board display"""
    db = get_db()
    flights = db.execute(
        "SELECT * FROM flights ORDER BY scheduled_departure"
    ).fetchall()
    return render_template_string(DISPLAY_TEMPLATE,
                                  flights=flights,
                                  now=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))


@app.route('/api/flights')
def api_flights():
    """JSON API for flight data"""
    db = get_db()
    flights = db.execute(
        "SELECT * FROM flights ORDER BY scheduled_departure").fetchall()
    return jsonify({'flights': [dict(f) for f in flights]})


@app.route('/admin')
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """
    Admin login page.

    VULNERABILITY: No brute force protection
    VULNERABILITY: No account lockout
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        # VULNERABILITY: plaintext password comparison
        user = db.execute(
            "SELECT * FROM admin_users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        if user:
            db.execute("UPDATE admin_users SET last_login = ? WHERE id = ?",
                       (datetime.utcnow().isoformat(), user['id']))
            db.commit()
            return admin_panel()
        return render_template_string(ADMIN_LOGIN_TEMPLATE, error="Invalid credentials")
    return render_template_string(ADMIN_LOGIN_TEMPLATE, error=None)


@app.route('/admin/panel')
def admin_panel():
    """
    Admin panel - shows system info and flight management.

    VULNERABILITY: No session management - relies on direct URL access
    VULNERABILITY: Information disclosure
    """
    db = get_db()
    flights = db.execute(
        "SELECT * FROM flights ORDER BY scheduled_departure").fetchall()
    count = db.execute("SELECT COUNT(*) as c FROM flights").fetchone()['c']
    return render_template_string(ADMIN_PANEL_TEMPLATE,
                                  flights=flights,
                                  flight_count=count,
                                  db_path=DB_PATH,
                                  dcs_url=DCS_API_URL,
                                  redis_host=REDIS_HOST,
                                  redis_port=REDIS_PORT,
                                  query=None)


@app.route('/admin/search')
def admin_search():
    """
    Search flights in admin panel.

    VULNERABILITY: SQL injection via search parameter.
    Query parameter 'q' is concatenated directly into SQL.
    """
    query = request.args.get('q', '')
    db = get_db()
    # VULNERABILITY: SQL injection
    sql = f"SELECT * FROM flights WHERE flight_number LIKE '%{query}%' OR destination LIKE '%{query}%'"
    try:
        flights = db.execute(sql).fetchall()
    except Exception as e:
        # VULNERABILITY: error message reveals database structure
        return jsonify({'error': f'Query failed: {str(e)}'}), 500

    count = db.execute("SELECT COUNT(*) as c FROM flights").fetchone()['c']
    return render_template_string(ADMIN_PANEL_TEMPLATE,
                                  flights=flights,
                                  flight_count=count,
                                  db_path=DB_PATH,
                                  dcs_url=DCS_API_URL,
                                  redis_host=REDIS_HOST,
                                  redis_port=REDIS_PORT,
                                  query=query)


@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'system': 'FIDS', 'version': '1.3.2'})


# ============================================================
# Start
# ============================================================

if __name__ == '__main__':
    init_db()
    seed_from_dcs()
    sub_thread = threading.Thread(target=redis_subscriber, daemon=True)
    sub_thread.start()
    app.run(host='0.0.0.0', port=5001, debug=True)
