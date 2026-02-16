"""
Flight Information Display System (FIDS) - Web Interface
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
import os
import re

app = Flask(__name__)

# Secret key for sessions
app.secret_key = os.environ.get(
    'SECRET_KEY', 'airport_fids_secret_2026')

# Session timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Logging enabled
logging.basicConfig(
    filename='/app/data/fids_access.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DATABASE = '/app/data/flights.db'


@app.context_processor
def inject_now():
    return {'now': datetime.now}


def get_db():
    """Get database connection"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initialise database with schema and sample data"""
    with app.app_context():
        db = get_db()

        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                failed_attempts INTEGER DEFAULT 0,
                last_failed_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS flights (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flight_number TEXT NOT NULL,
                airline TEXT NOT NULL,
                departure_airport TEXT NOT NULL,
                arrival_airport TEXT NOT NULL,
                scheduled_departure TIMESTAMP NOT NULL,
                scheduled_arrival TIMESTAMP NOT NULL,
                status TEXT NOT NULL,
                gate TEXT,
                terminal TEXT,
                aircraft_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                username TEXT,
                action TEXT,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')

        # Password hashing - SHA256 without salt
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        operator_password = hashlib.sha256('operator2024'.encode()).hexdigest()

        try:
            db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                       ('admin', admin_password, 'admin'))
            db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                       ('operator', operator_password, 'user'))
        except sqlite3.IntegrityError:
            pass

        sample_flights = [
            ('BA123', 'British Airways', 'LHR', 'JFK',
             '2026-01-19 10:30:00', '2026-01-19 18:45:00', 'On Time', 'A12', 'T5', 'Boeing 777'),
            ('EK456', 'Emirates', 'LHR', 'DXB',
             '2026-01-19 14:00:00', '2026-01-19 23:30:00', 'Boarding', 'B23', 'T3', 'Airbus A380'),
            ('SQ789', 'Singapore Airlines', 'LHR', 'SIN',
             '2026-01-19 11:15:00', '2026-01-20 06:30:00', 'Delayed', 'C34', 'T2', 'Airbus A350'),
            ('AF321', 'Air France', 'LHR', 'CDG',
             '2026-01-19 16:20:00', '2026-01-19 18:45:00', 'Departed', 'D45', 'T4', 'Airbus A320'),
            ('BA987', 'British Airways', 'JFK', 'LHR',
             '2026-01-19 20:00:00', '2026-01-20 08:15:00', 'Scheduled', 'E56', 'T5', 'Boeing 787'),
        ]

        for flight in sample_flights:
            try:
                db.execute('''
                    INSERT INTO flights (flight_number, airline, departure_airport, 
                                       arrival_airport, scheduled_departure, scheduled_arrival,
                                       status, gate, terminal, aircraft_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', flight)
            except sqlite3.IntegrityError:
                pass

        db.commit()

# =============================================================================
# SECURITY FUNCTIONS
# =============================================================================


def login_required(f):
    """Require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        db = get_db()
        user = db.execute('SELECT role FROM users WHERE id = ?',
                          (session['user_id'],)).fetchone()

        if not user or user['role'] != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function


def log_action(action):
    """Log user actions"""
    db = get_db()
    username = session.get('username', 'anonymous')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')

    db.execute('''
        INSERT INTO audit_log (username, action, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
    ''', (username, action, ip_address, user_agent))
    db.commit()

    logging.info(f"Action: {action} | User: {username} | IP: {ip_address}")


def validate_input(text, pattern=None):
    """
    Basic input validation
    Vulnerability: Regex can be bypassed
    """
    if not text:
        return False

    # Block obvious SQL injection keywords
    # Vulnerability: Case-sensitive, can be bypassed with encoded inputs
    dangerous_keywords = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'EXEC', '--']
    for keyword in dangerous_keywords:
        if keyword in text.upper():
            return False

    if pattern:
        return re.match(pattern, text) is not None

    return True

# =============================================================================
# ROUTES
# =============================================================================


@app.route('/')
def index():
    """Home page - Display flights"""
    db = get_db()
    search_query = request.args.get('q', '')

    query = '''
        SELECT * FROM flights 
        WHERE 1=1
    '''
    params = []

    if search_query:
        # Parameterised query for search
        query += '''
            AND (flight_number LIKE ? 
            OR airline LIKE ? 
            OR departure_airport LIKE ? 
            OR arrival_airport LIKE ? 
            OR status LIKE ?)
        '''
        search_pattern = f'%{search_query}%'
        params = [search_pattern] * 5

    query += ' ORDER BY scheduled_departure ASC'

    if params:
        flights = db.execute(query, params).fetchall()
    else:
        flights = db.execute(query).fetchall()

    return render_template('index.html', flights=flights, search_query=search_query)


@app.route('/flight/<int:flight_id>')
def flight_detail(flight_id):
    """Display detailed flight information"""
    db = get_db()

    flight = db.execute('SELECT * FROM flights WHERE id = ?',
                        (flight_id,)).fetchone()

    if not flight:
        flash('Flight not found.', 'warning')
        return redirect(url_for('index'))

    return render_template('flight_detail.html', flight=flight)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login with password hashing, failed attempt tracking
    Vulnerabilities: Weak hashing (SHA256 no salt), no rate limiting, long session timeout
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password required.', 'danger')
            return render_template('login.html')

        db = get_db()

        # Parameterised query prevents SQL injection in login
        user = db.execute('SELECT * FROM users WHERE username = ?',
                          (username,)).fetchone()

        if user:
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            if password_hash == user['password']:
                # Successful login
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']

                # Reset failed attempts
                db.execute('UPDATE users SET failed_attempts = 0 WHERE id = ?',
                           (user['id'],))
                db.commit()

                log_action(f"Successful login")
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('admin_panel' if user['role'] == 'admin' else 'index'))
            else:
                # Failed login - track attempts but no account lockout
                failed_attempts = user['failed_attempts'] + 1
                db.execute('''
                    UPDATE users 
                    SET failed_attempts = ?, last_failed_login = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (failed_attempts, user['id']))
                db.commit()

                log_action(f"Failed login attempt for user: {username}")
                flash('Invalid credentials.', 'danger')
        else:
            log_action(f"Failed login attempt for unknown user: {username}")
            flash('Invalid credentials.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username', 'unknown')
    session.clear()
    log_action(f"Logout: {username}")
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_panel():
    """
    Admin panel with role-based access control
    Vulnerability: Session fixation possible - sessions not regenerated
    """
    db = get_db()

    # Get all flights for management
    flights = db.execute('''
        SELECT * FROM flights 
        ORDER BY scheduled_departure ASC
    ''').fetchall()

    # Get recent logs
    logs = db.execute('''
        SELECT * FROM audit_log 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''').fetchall()

    # Get user statistics
    users = db.execute('SELECT * FROM users').fetchall()

    log_action("Accessed admin panel")
    return render_template('admin.html', flights=flights, logs=logs, users=users)


@app.route('/admin/update_flight/<int:flight_id>', methods=['POST'])
@admin_required
def update_flight(flight_id):
    """
    Update flight status (admin only)
    Vulnerability: XSS - status updates not sanitised before display
    """
    new_status = request.form.get('status', '')

    if not validate_input(new_status):
        flash('Invalid status value.', 'danger')
        return redirect(url_for('admin_panel'))

    db = get_db()

    # Vulnerability: XSS - no output encoding when displaying status
    db.execute('''
        UPDATE flights 
        SET status = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (new_status, flight_id))
    db.commit()

    log_action(f"Updated flight {flight_id} status to: {new_status}")
    flash('Flight status updated.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'operational', 'timestamp': datetime.now().isoformat()}

# =============================================================================
# ERROR HANDLERS
# =============================================================================


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal error: {error}")
    return render_template('500.html'), 500

# =============================================================================
# MAIN
# =============================================================================


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
