"""Database initialisation for FIDS"""
import sqlite3
import os
import hashlib


def init_database():
    """Initialise SQLite database with sample flight data"""

    db_path = '/app/data/flights.db'
    os.makedirs('/app/data', exist_ok=True)

    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Flights Table
    cursor.execute('''
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

    # Users Table
    cursor.execute('''
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

    # Audit Log Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')

    # Insert sample flights
    flights = [
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

    cursor.executemany('''
        INSERT INTO flights (
            flight_number, airline, departure_airport, arrival_airport,
            scheduled_departure, scheduled_arrival, status, gate, terminal, aircraft_type
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', flights)

    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    operator_password = hashlib.sha256('operator2024'.encode()).hexdigest()

    cursor.execute('''
        INSERT INTO users (username, password, role)
        VALUES (?, ?, ?)
    ''', ('admin', admin_password, 'admin'))

    cursor.execute('''
        INSERT INTO users (username, password, role)
        VALUES (?, ?, ?)
    ''', ('operator', operator_password, 'user'))

    conn.commit()
    conn.close()

    print("Database successfully initialised")
    print("Default credentials:")
    print("Username: admin | Password: admin123 (admin role)")
    print("Username: operator | Password: operator2024 (user role)")


if __name__ == '__main__':
    init_database()
