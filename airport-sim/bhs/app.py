"""
Baggage Handling System (BHS)
Peripheral System (Internal OT)

Subscribes to DCS baggage routing via Redis pub/sub.
Provides internal baggage tracking API and maintenance interface.

Intentional Vulnerabilities:
- Command injection on maintenance diagnostic endpoint
- Default PostgreSQL credentials
- Outdated software simulation (known CVE patterns)
- API key exposed in system config
- No authentication on tracking endpoints
- Information disclosure via maintenance API
- Shared service accounts
"""

import os
import json
import hashlib
import subprocess
import threading
from datetime import datetime

import psycopg2
import psycopg2.extras
import redis
from flask import Flask, request, jsonify, g

app = Flask(__name__)

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'bhs-db'),
    'port': os.environ.get('DB_PORT', '5433'),
    'dbname': os.environ.get('DB_NAME', 'bhs'),
    'user': os.environ.get('DB_USER', 'bhs_user'),
    'password': os.environ.get('DB_PASSWORD', 'bhs_password')
}

REDIS_HOST = os.environ.get('REDIS_HOST', 'redis')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))


def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(**DB_CONFIG)
        g.db.autocommit = True
    return g.db


def get_cursor():
    return get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db:
        db.close()


# ============================================================
# Redis subscriber - listens for DCS baggage routing
# ============================================================

def redis_subscriber():
    """Background thread subscribing to DCS baggage routing instructions"""
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                        decode_responses=True)
        pubsub = r.pubsub()
        pubsub.subscribe('bhs:routing')
        print("[BHS] Subscribed to bhs:routing channel")

        for message in pubsub.listen():
            if message['type'] == 'message':
                try:
                    payload = json.loads(message['data'])
                    bag_data = payload.get('data', {})
                    process_bag_routing(bag_data)
                    print(f"[BHS] Processed bag {bag_data.get('tag_id', '?')}")
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"[BHS] Error processing message: {e}")
    except Exception as e:
        print(f"[BHS] Redis subscriber error: {e}")


def process_bag_routing(bag_data):
    """Process incoming baggage routing instruction from DCS"""
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO baggage_tracking (tag_id, passenger_id, flight_id, flight_number, weight_kg, status, current_zone)
            VALUES (%s, %s, %s, %s, %s, 'received', 'intake')
            ON CONFLICT (tag_id) DO UPDATE SET status = 'received', current_zone = 'intake', last_scan = NOW()
        """, (
            bag_data.get('tag_id'),
            bag_data.get('passenger_id'),
            bag_data.get('flight_id'),
            bag_data.get('flight_number'),
            bag_data.get('weight_kg', 0)
        ))
        # Log zone entry
        cur.execute("""
            INSERT INTO zone_log (tag_id, zone, conveyor_id) VALUES (%s, 'intake', 'CV-01')
        """, (bag_data.get('tag_id'),))
    except Exception as e:
        print(f"[BHS] DB error: {e}")
    finally:
        cur.close()
        conn.close()


# ============================================================
# API Routes
# ============================================================

@app.route('/api/health')
def health():
    try:
        cur = get_cursor()
        cur.execute("SELECT 1")
        cur.close()
        return jsonify({'status': 'healthy', 'system': 'Baggage Handling System', 'version': '4.2.1'})
    except:
        return jsonify({'status': 'unhealthy'}), 503


@app.route('/api/track/<tag_id>')
def track_bag(tag_id):
    """
    Track bag by tag ID.

    VULNERABILITY: No authentication required.
    Exposes passenger_id. Enables PII correlation with DCS data.
    """
    cur = get_cursor()
    cur.execute("SELECT * FROM baggage_tracking WHERE tag_id = %s", (tag_id,))
    bag = cur.fetchone()

    if not bag:
        cur.close()
        return jsonify({'error': 'Tag not found'}), 404

    # Get zone history
    cur.execute(
        "SELECT * FROM zone_log WHERE tag_id = %s ORDER BY scanned_at", (tag_id,))
    history = cur.fetchall()
    cur.close()

    for item in [bag] + history:
        for key in ['received_at', 'last_scan', 'scanned_at']:
            if item.get(key):
                item[key] = item[key].isoformat()

    return jsonify({'bag': bag, 'zone_history': history})


@app.route('/api/flight/<flight_number>/bags')
def flight_bags(flight_number):
    """
    Get all bags for a flight.

    VULNERABILITY: No authentication. Exposes passenger IDs for correlation.
    """
    cur = get_cursor()
    cur.execute(
        "SELECT * FROM baggage_tracking WHERE flight_number = %s ORDER BY received_at", (flight_number,))
    bags = cur.fetchall()
    cur.close()

    for bag in bags:
        for key in ['received_at', 'last_scan']:
            if bag.get(key):
                bag[key] = bag[key].isoformat()

    return jsonify({'flight': flight_number, 'bag_count': len(bags), 'bags': bags})


@app.route('/api/scan', methods=['POST'])
def scan_bag():
    """
    Record bag scan at a zone checkpoint.
    Updates bag status and location.
    """
    data = request.get_json()
    tag_id = data.get('tag_id', '')
    zone = data.get('zone', '')
    conveyor = data.get('conveyor_id', '')

    if not tag_id or not zone:
        return jsonify({'error': 'tag_id and zone required'}), 400

    # Map zones to statuses
    zone_status_map = {
        'intake': 'received',
        'screening': 'screening',
        'security_cleared': 'security_cleared',
        'sorting': 'sorting',
        'loading': 'loading',
        'loaded': 'loaded',
        'delivered': 'delivered'
    }
    new_status = zone_status_map.get(zone, 'in_transit')

    cur = get_cursor()
    cur.execute("""
        UPDATE baggage_tracking SET status = %s, current_zone = %s, conveyor_id = %s, last_scan = NOW()
        WHERE tag_id = %s RETURNING *
    """, (new_status, zone, conveyor, tag_id))
    bag = cur.fetchone()

    if not bag:
        cur.close()
        return jsonify({'error': 'Tag not found'}), 404

    cur.execute("INSERT INTO zone_log (tag_id, zone, conveyor_id) VALUES (%s, %s, %s)",
                (tag_id, zone, conveyor))
    cur.close()

    return jsonify({'message': 'Scan recorded', 'tag_id': tag_id, 'zone': zone, 'status': new_status})


@app.route('/api/maintenance/config')
def maintenance_config():
    """
    Maintenance configuration endpoint.

    VULNERABILITY: No authentication required.
    VULNERABILITY: Exposes sensitive configuration including API keys and internal endpoints.
    """
    cur = get_cursor()
    cur.execute(
        "SELECT config_key, config_value, last_modified FROM system_config ORDER BY config_key")
    config = cur.fetchall()
    cur.close()

    for item in config:
        if item.get('last_modified'):
            item['last_modified'] = item['last_modified'].isoformat()

    return jsonify({'system_config': config})


@app.route('/api/maintenance/diagnostic', methods=['POST'])
def run_diagnostic():
    """
    Run system diagnostic command.

    VULNERABILITY: Command injection. 'target' parameter is passed directly to subprocess 
    without sanitisation.
    """
    data = request.get_json()
    target = data.get('target', '')

    if not target:
        return jsonify({'error': 'Target required (e.g., hostname or IP)'}), 400

    try:
        # VULNERABILITY: command injection - target is not sanitised
        result = subprocess.run(
            f"ping -c 2 {target}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return jsonify({
            'diagnostic': 'ping',
            'target': target,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Diagnostic timed out'}), 504
    except Exception as e:
        # VULNERABILITY: error reveals system details
        return jsonify({'error': f'Diagnostic failed: {str(e)}'}), 500


@app.route('/api/stats')
def stats():
    """Baggage system statistics"""
    cur = get_cursor()
    cur.execute("""
        SELECT status, COUNT(*) as count FROM baggage_tracking GROUP BY status
    """)
    by_status = cur.fetchall()
    cur.execute("SELECT COUNT(*) as total FROM baggage_tracking")
    total = cur.fetchone()['total']
    cur.close()

    return jsonify({'total_bags': total, 'by_status': by_status})


# ============================================================
# Start
# ============================================================

if __name__ == '__main__':
    sub_thread = threading.Thread(target=redis_subscriber, daemon=True)
    sub_thread.start()
    app.run(host='0.0.0.0', port=5003, debug=True)
