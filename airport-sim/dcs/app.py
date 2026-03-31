"""
Departure Control System (DCS) - Central Hub

Intentional Vulnerabilities:
- JWT algorithm confusion (HS256/none)
- Mass assignment on check-in endpoint
- No audit logging
- No role-based access control enforcement
- MD5 password hashing
- SQL injection on passenger lookup
- IDOR on booking retrieval
- Unencrypted inter-service communication
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

import jwt
import psycopg2
import psycopg2.extras
import redis
from flask import Flask, request, jsonify, g
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'dcs-db'),
    'port': os.environ.get('DB_PORT', '5432'),
    'dbname': os.environ.get('DB_NAME', 'dcs'),
    'user': os.environ.get('DB_USER', 'dcs_user'),
    'password': os.environ.get('DB_PASSWORD', 'dcs_password')
}

REDIS_HOST = os.environ.get('REDIS_HOST', 'redis')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))

# VULNERABILITY: Weak JWT secret, susceptible to brute force
JWT_SECRET = os.environ.get('JWT_SECRET', 'airport-secret-key-2024')
JWT_ALGORITHM = 'HS256'


def get_db():
    """Get database connection from application context."""
    if 'db' not in g:
        g.db = psycopg2.connect(**DB_CONFIG)
        g.db.autocommit = True
    return g.db


def get_cursor():
    """Get a RealDictCursor for JSON-friendly results."""
    return get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def get_redis():
    """Get Redis connection for pub/sub messaging."""
    if 'redis' not in g:
        g.redis = redis.Redis(
            host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return g.redis


# ============================================================
# Authentication helpers
# ============================================================

def generate_token(user_data):
    """
    Generate JWT token for staff authentication.

    VULNERABILITY: JWT algorithm confusion
    - Uses HS256 but does not enforce algorithm on verification
    - Attacker can forge tokens using 'none' algorithm
    """
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'exp': datetime.utcnow() + timedelta(hours=8)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token):
    """
    Verify JWT token.

    VULNERABILITY: Does not restrict allowed algorithms.
    An attacker can use algorithm='none' to bypass signature verification.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[
                             JWT_ALGORITHM, 'none'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return {'error': 'Token required'}, 401
        payload = verify_token(token)
        if payload is None:
            return {'error': 'Invalid or expired token'}, 401
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Decorator to require admin role.

    VULNERABILITY: Only checks token claim, does not verify against database.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return {'error': 'Admin access required'}, 403
        return f(*args, **kwargs)
    return decorated


# ============================================================
# Pub/Sub helpers (MQTT-like via Redis)
# ============================================================

def publish_flight_update(flight_data):
    """Publish flight status update to FIDS channel"""
    try:
        r = get_redis()
        message = json.dumps({
            'event': 'flight_update',
            'timestamp': datetime.utcnow().isoformat(),
            'data': flight_data
        })
        r.publish('fids:updates', message)
    except Exception:
        pass  # VULNERABILITY: silent failure, no logging


def publish_baggage_instruction(baggage_data):
    """Publish baggage routing instruction to BHS channel"""
    try:
        r = get_redis()
        message = json.dumps({
            'event': 'baggage_route',
            'timestamp': datetime.utcnow().isoformat(),
            'data': baggage_data
        })
        r.publish('bhs:routing', message)
    except Exception:
        pass  # VULNERABILITY: silent failure, no logging


# ============================================================
# API Resources
# ============================================================

class StaffLogin(Resource):
    """
    Staff authentication endpoint.

    VULNERABILITY: MD5 password hashing
    """

    def post(self):
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')

        cur = get_cursor()
        cur.execute(
            "SELECT id, username, full_name, role, password_hash FROM staff WHERE username = %s AND is_active = true",
            (username,)
        )
        user = cur.fetchone()
        cur.close()

        if not user:
            return {'error': f'User \'{username}\' not found'}, 404

        # VULNERABILITY: MD5 comparison
        if user['password_hash'] != hashlib.md5(password.encode()).hexdigest():
            return {'error': 'Incorrect password'}, 401

        token = generate_token(user)
        return {
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'full_name': user['full_name'],
                'role': user['role']
            }
        }, 200


class FlightList(Resource):
    """List all flights"""

    def get(self):
        status_filter = request.args.get('status', None)
        cur = get_cursor()

        if status_filter:
            cur.execute(
                "SELECT * FROM flights WHERE status = %s ORDER BY scheduled_departure", (status_filter,))
        else:
            cur.execute("SELECT * FROM flights ORDER BY scheduled_departure")

        flights = cur.fetchall()
        cur.close()

        # Convert timestamps to strings for JSON serialisation
        for f in flights:
            for key in ['scheduled_departure', 'estimated_departure', 'created_at']:
                if f.get(key):
                    f[key] = f[key].isoformat()

        return {'flights': flights}, 200


class FlightDetail(Resource):
    """Get or update a specific flight"""

    def get(self, flight_number):
        cur = get_cursor()
        cur.execute(
            "SELECT * FROM flights WHERE flight_number = %s", (flight_number,))
        flight = cur.fetchone()
        cur.close()

        if not flight:
            return {'error': 'Flight not found'}, 404

        for key in ['scheduled_departure', 'estimated_departure', 'created_at']:
            if flight.get(key):
                flight[key] = flight[key].isoformat()

        return {'flight': flight}, 200

    @token_required
    def put(self, flight_number):
        """
        Update flight status/gate.
        Publishes update to FIDS via Redis pub/sub.
        """
        data = request.get_json()
        cur = get_cursor()

        allowed_fields = ['gate', 'status', 'estimated_departure']
        updates = []
        values = []
        for field in allowed_fields:
            if field in data:
                updates.append(f"{field} = %s")
                values.append(data[field])

        if not updates:
            return {'error': 'No valid fields to update'}, 400

        values.append(flight_number)
        query = f"UPDATE flights SET {', '.join(updates)} WHERE flight_number = %s RETURNING *"
        cur.execute(query, values)
        flight = cur.fetchone()
        cur.close()

        if not flight:
            return {'error': 'Flight not found'}, 404

        for key in ['scheduled_departure', 'estimated_departure', 'created_at']:
            if flight.get(key):
                flight[key] = flight[key].isoformat()

        publish_flight_update(flight)

        return {'flight': flight, 'message': 'Flight updated and published to FIDS'}, 200


class PassengerLookup(Resource):
    """
    Look up passenger by passport number or name.

    VULNERABILITY: SQL injection on search parameter.
    """
    @token_required
    def get(self):
        search = request.args.get('search', '')

        if not search:
            return {'error': 'Search parameter required'}, 400

        cur = get_cursor()
        # VULNERABILITY: SQL injection - string formatting
        query = f"SELECT id, first_name, last_name, email, passport_number, nationality FROM passengers WHERE passport_number = '{search}' OR last_name ILIKE '%{search}%'"
        try:
            cur.execute(query)
            passengers = cur.fetchall()
        except Exception as e:
            # VULNERABILITY: error message exposes database details
            return {'error': f'Database error: {str(e)}'}, 500
        finally:
            cur.close()

        return {'passengers': passengers}, 200


class BookingDetail(Resource):
    """
    Retrieve booking by reference.

    VULNERABILITY: IDOR - no authorisation check on who can view a booking.
    """
    @token_required
    def get(self, reference):
        cur = get_cursor()
        cur.execute("""
            SELECT b.*, p.first_name, p.last_name, p.passport_number, p.email,
                   f.flight_number, f.origin, f.destination, f.scheduled_departure, f.gate, f.status as flight_status
            FROM bookings b
            JOIN passengers p ON b.passenger_id = p.id
            JOIN flights f ON b.flight_id = f.id
            WHERE b.reference = %s
        """, (reference,))
        booking = cur.fetchone()
        cur.close()

        if not booking:
            return {'error': 'Booking not found'}, 404

        for key in ['scheduled_departure', 'created_at']:
            if booking.get(key):
                booking[key] = booking[key].isoformat()

        return {'booking': booking}, 200


class CheckIn(Resource):
    """
    Check-in endpoint: processes passenger check-in, generates boarding pass,
    creates baggage record, and publishes to BHS.

    VULNERABILITY: Mass assignment - accepts arbitrary fields from request body.
    Attacker can set role, travel_class, seat_number.
    """
    @token_required
    def post(self):
        data = request.get_json()
        reference = data.get('booking_reference', '')
        bags = data.get('bags', [])

        cur = get_cursor()

        # Look up booking
        cur.execute("""
            SELECT b.*, f.flight_number, f.status as flight_status, f.origin
            FROM bookings b
            JOIN flights f ON b.flight_id = f.id
            WHERE b.reference = %s
        """, (reference,))
        booking = cur.fetchone()

        if not booking:
            cur.close()
            return {'error': 'Booking not found'}, 404

        if booking['booking_status'] == 'checked_in':
            cur.close()
            return {'error': 'Already checked in'}, 400

        if booking['flight_status'] in ('departed', 'cancelled'):
            cur.close()
            return {'error': f'Flight is {booking["flight_status"]}'}, 400

        # Assign seat
        # VULNERABILITY: Mass assignment
        seat = data.get('seat_number', None)
        if not seat:
            cur.execute("""
                SELECT seat_number FROM bookings
                WHERE flight_id = %s AND seat_number IS NOT NULL
            """, (booking['flight_id'],))
            taken = {row['seat_number'] for row in cur.fetchall()}
            for row_num in range(1, 40):
                for col in ['A', 'B', 'C', 'D', 'E', 'F']:
                    candidate = f"{row_num}{col}"
                    if candidate not in taken:
                        seat = candidate
                        break
                if seat:
                    break

        travel_class = data.get('travel_class', booking['travel_class'])
        boarding_group = 'A' if travel_class in ('first', 'business') else 'B'

        # Update booking
        cur.execute("""
            UPDATE bookings SET booking_status = 'checked_in', seat_number = %s, travel_class = %s
            WHERE id = %s
        """, (seat, travel_class, booking['id']))

        # Generate boarding pass with JWT
        bp_payload = {
            'booking_ref': reference,
            'passenger_id': booking['passenger_id'],
            'flight': booking['flight_number'],
            'seat': seat,
            'boarding_group': boarding_group,
            'class': travel_class,
            'issued': datetime.utcnow().isoformat()
        }
        barcode = jwt.encode(bp_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        cur.execute("""
            INSERT INTO boarding_passes (booking_id, passenger_id, flight_id, seat_number, boarding_group, barcode_data)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """, (booking['id'], booking['passenger_id'], booking['flight_id'], seat, boarding_group, barcode))
        bp = cur.fetchone()

        # Create baggage records and publish to BHS
        baggage_records = []
        for i, bag in enumerate(bags):
            tag_id = f"{booking['origin']}-{booking['flight_number']}-{booking['passenger_id']:03d}-{i+1}"
            weight = bag.get('weight_kg', 0)

            cur.execute("""
                INSERT INTO baggage (tag_id, passenger_id, flight_id, booking_id, weight_kg, status, current_location)
                VALUES (%s, %s, %s, %s, %s, 'checked_in', 'check-in')
                RETURNING id, tag_id
            """, (tag_id, booking['passenger_id'], booking['flight_id'], booking['id'], weight))
            bag_record = cur.fetchone()
            baggage_records.append(bag_record)

            publish_baggage_instruction({
                'tag_id': tag_id,
                'passenger_id': booking['passenger_id'],
                'flight_id': booking['flight_id'],
                'flight_number': booking['flight_number'],
                'weight_kg': float(weight),
                'action': 'route_to_screening'
            })

        cur.close()

        return {
            'message': 'Check-in successful',
            'boarding_pass': {
                'id': bp['id'],
                'seat': seat,
                'boarding_group': boarding_group,
                'class': travel_class,
                'barcode': barcode
            },
            'baggage_tags': [{'tag_id': b['tag_id']} for b in baggage_records]
        }, 201


class PassengerManifest(Resource):
    """
    Get passenger manifest for a flight.

    VULNERABILITY: No role check - any authenticated user can
    access full passenger manifest.
    """
    @token_required
    def get(self, flight_number):
        cur = get_cursor()
        cur.execute("""
            SELECT p.first_name, p.last_name, p.passport_number, p.nationality,
                   b.reference, b.seat_number, b.travel_class, b.booking_status,
                   bp.boarding_group, bp.barcode_data
            FROM bookings b
            JOIN passengers p ON b.passenger_id = p.id
            JOIN flights f ON b.flight_id = f.id
            LEFT JOIN boarding_passes bp ON bp.booking_id = b.id
            WHERE f.flight_number = %s
            ORDER BY b.seat_number
        """, (flight_number,))
        manifest = cur.fetchall()
        cur.close()

        return {
            'flight': flight_number,
            'passenger_count': len(manifest),
            'manifest': manifest
        }, 200


class BaggageStatus(Resource):
    """Query baggage status by tag ID"""
    @token_required
    def get(self, tag_id):
        cur = get_cursor()
        cur.execute("""
            SELECT bg.*, p.first_name, p.last_name, f.flight_number
            FROM baggage bg
            JOIN passengers p ON bg.passenger_id = p.id
            JOIN flights f ON bg.flight_id = f.id
            WHERE bg.tag_id = %s
        """, (tag_id,))
        bag = cur.fetchone()
        cur.close()

        if not bag:
            return {'error': 'Baggage tag not found'}, 404

        for key in ['created_at', 'updated_at']:
            if bag.get(key):
                bag[key] = bag[key].isoformat()

        return {'baggage': bag}, 200


class SystemInfo(Resource):
    """
    System information endpoint.

    VULNERABILITY: Information disclosure - exposes internal system details
    including database version, Python version, and configuration.
    No authentication requirement.
    """

    def get(self):
        cur = get_cursor()
        cur.execute("SELECT version()")
        db_version = cur.fetchone()['version']
        cur.close()

        return {
            'system': 'Departure Control System (DCS)',
            'version': '2.1.4',
            'database': db_version,
            'api_framework': 'Flask-RESTful',
            'message_broker': f'Redis @ {REDIS_HOST}:{REDIS_PORT}',
            'endpoints': [rule.rule for rule in app.url_map.iter_rules() if not rule.rule.startswith('/static')],
            'status': 'operational'
        }, 200


# ============================================================
# Health check for Docker
# ============================================================

class HealthCheck(Resource):
    def get(self):
        try:
            cur = get_cursor()
            cur.execute("SELECT 1")
            cur.close()
            r = get_redis()
            r.ping()
            return {'status': 'healthy', 'database': 'connected', 'redis': 'connected'}, 200
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}, 503


# ============================================================
# Register routes
# ============================================================

api.add_resource(HealthCheck,       '/api/health')
api.add_resource(SystemInfo,        '/api/system')
api.add_resource(StaffLogin,        '/api/auth/login')
api.add_resource(FlightList,        '/api/flights')
api.add_resource(FlightDetail,      '/api/flights/<string:flight_number>')
api.add_resource(PassengerLookup,   '/api/passengers')
api.add_resource(BookingDetail,     '/api/bookings/<string:reference>')
api.add_resource(CheckIn,           '/api/checkin')
api.add_resource(PassengerManifest, '/api/manifest/<string:flight_number>')
api.add_resource(BaggageStatus,     '/api/baggage/<string:tag_id>')


# ============================================================
# Entry point
# ============================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
