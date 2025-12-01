"""Databse initialisation for FIDS"""
import sqlite3
import os


def init_database():
    """Initialise SQLite database with sample flight data"""

    if os.path.exists('flights.db'):
        os.remove('flights.db')

    conn = sqlite3.connect('flights.db')
    cursor = conn.cursor()

    # Flights Table
    cursor.execute('''
                   CREATE TABLE flights (
                        id INTEGER PRIMARY KEY AUTO INCREMENT,
                        flight_number TEXT NOT NULL,
                        airline TEXT NOT NULL
                        departure_city TEXT NOT NULL,
                        arrival_city TEXT NOT NULL,
                        departure_time TEXT NOT NULL,
                        arrival_time TEXT NOT NULL,
                        status TEXT NOT NULL,
                        gate TEXT NOT NULL
                   )
                ''')

    # Users Table
    cursor.execute('''
                   CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL
                   )
                ''')

    flights = [
        ('BA123', 'British Airways', 'London',
         'New York', '10:00', '13:00', 'On Time', 'A12'),
        ('AA456', 'American Airlines', 'New York',
         'Los Angeles', '14:30', '17:45', 'Delayed', 'B7'),
        ('LH789', 'Lufthansa', 'Frankfurt', 'Tokyo',
         '09:15', '05:30+1', 'On Time', 'C3'),
        ('EK234', 'Emirates', 'Dubai', 'London',
         '02:45', '07:15', 'Boarding', 'D9'),
        ('QF567', 'Qantas', 'Sydney', 'Singapore',
         '23:00', '05:30+1', 'On Time', 'E5'),
        ('AF890', 'Air France', 'Paris', 'Montreal',
         '11:20', '13:45', 'On Time', 'F2'),
        ('UA321', 'United Airlines', 'Chicago',
         'London', '18:00', '07:30+1', 'Delayed', 'G8'),
        ('SQ654', 'Singapore Airlines', 'Singapore',
         'London', '23:45', '06:15+1', 'On Time', 'H4'),
        ('DL987', 'Delta', 'Atlanta', 'Amsterdam',
         '17:30', '07:45+1', 'Cancelled', 'I1'),
        ('KL246', 'KLM', 'Amsterdam', 'Beijing',
         '13:10', '05:30+1', 'On Time', 'J6')
    ]

    cursor.executemany('''
                       INSERT INTO flights (flight_number, airline, departure_city, arrival_city, departure_time, arrival_time, status, gate)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ''', flights)

    # Admin with weak credentials
    cursor.execute('''
                   INSERT INTO users (username, password, role)
                   VALUES (?, ?, ?)
                   ''', ('admin', 'admin123', 'administrator'))

    # Regular user
    cursor.execute('''
                   INSERT INTO users (username, password, role)
                   VALUES (?, ?, ?)
                   ''', ('user', 'password', 'user'))

    conn.commit()
    conn.close()

    print("Database successfully initialised")
    print("WARNING: Default credentials in use!")
    print("Username: admin | Password: admin123")


if __name__ == '__main__':
    init_database()
