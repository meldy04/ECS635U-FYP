import sqlite3
from flask import Flask, render_template, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'my_top_secret_key123'


def get_db_connection():
    """Database connection helper"""
    conn = sqlite3.connect('flights.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    """Display homepage with flight board"""
    conn = get_db_connection()

    flights = conn.execute(
        'SELECT * FROM flights ORDER BY departure_time').fetchall()
    conn.close()

    return render_template('index.html', flights=flights)


@app.route('/search', methods=['GET', 'POST'])
def search():
    """VULNERABILITY 1: SQL Injection - Search for flights"""
    results = []
    search_query = ""

    if request.method == 'POST':
        search_query = request.form.get('query', '')

        conn = get_db_connection()
        sql = f"SELECT * FROM flights WHERE flight_number LIKE '%{search_query}%' OR airline LIKE '%{search_query}%' OR departure_city LIKE '%{search_query}%'"

        try:
            results = conn.execute(sql).fetchall()
        except Exception as e:
            results = [{'error': str(e)}]

        conn.close()

    return render_template('search.html', results=results, query=search_query)


@app.route('/flight/<flight_id>')
def flight_details(flight_id):
    """VULNERABILITY 2: Reflected XSS - Display flight details"""
    conn = get_db_connection()
    flight = conn.execute(
        'SELECT * FROM flights WHERE id = ?', (flight_id,)).fetchone()
    conn.close()

    if flight:
        return render_template('index.html', flights=[flight], message=f"Showing flight: {flight_id}")
    else:
        return f"<h1>Flight not found: {flight_id}</h1><a href='/'>Back to home</a>", 404


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    """VULNERABILITY 3: Weak Authentication - Admin Panel"""

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = get_db_connection()

        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()

        conn.close()

        if user:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user['role']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin.html', error="Invalid credentials")

    return render_template('admin.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard - requires authentication"""

    # VULNERABILITY: No timeout -> weak session
    if not session.get('logged_in'):
        return redirect(url_for('admin'))

    conn = get_db_connection()
    flights = conn.execute('SELECT * FROM flights').fetchall()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()

    return f"""
    <html>
    <head><title>Admin Dashboard</title></head>
    <body>
        <h1>Admin Dashboard</h1>
        <p>Hello, {session.get('username')}!</p>
        <h2>Total Flights: {len(flights)}</h2>
        <h2>Total Users: {len(users)}</h2>
        <a href='/admin/logout'>Logout</a>
    </body>
    </html>
    """


@app.route('/admin/logout')
def admin_logout():
    """Logout of admin panel"""
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
