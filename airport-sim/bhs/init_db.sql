-- ============================================================
-- BHS Database Schema
-- Internal OT system - receives routing from DCS via Redis
-- ============================================================

-- Baggage tracking: mirrors DCS baggage table with OT-specific fields
CREATE TABLE baggage_tracking (
    id SERIAL PRIMARY KEY,
    tag_id VARCHAR(20) UNIQUE NOT NULL,
    passenger_id INTEGER,
    flight_id INTEGER,
    flight_number VARCHAR(10),
    weight_kg DECIMAL(5, 2),
    status VARCHAR(30) DEFAULT 'received',
    current_zone VARCHAR(50) DEFAULT 'intake',
    conveyor_id VARCHAR(20),
    screening_result VARCHAR(20),
    loaded_uld VARCHAR(20),
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Zone tracking: logs bag movement through the system
CREATE TABLE zone_log (
    id SERIAL PRIMARY KEY,
    tag_id VARCHAR(20) REFERENCES baggage_tracking (tag_id),
    zone VARCHAR(50) NOT NULL,
    conveyor_id VARCHAR(20),
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System maintenance: exposed via maintenance API
-- VULNERABILITY: contains system configuration details
CREATE TABLE system_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Operators for BHS
-- VULNERABILITY: default credentials, shared service accounts
CREATE TABLE operators (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'operator',
    is_active BOOLEAN DEFAULT true
);

INSERT INTO
    system_config (config_key, config_value)
VALUES (
        'system_version',
        'BHS Controller v4.2.1'
    ),
    (
        'db_version',
        'PostgreSQL 14.2'
    ),
    ('conveyor_count', '12'),
    ('screening_lanes', '4'),
    (
        'max_throughput',
        '1800 bags/hour'
    ),
    ('maintenance_mode', 'false'),
    (
        'api_key',
        'bhs-internal-key-do-not-share-2024'
    ),
    (
        'dcs_endpoint',
        'http://dcs:5000'
    ),
    (
        'redis_channel',
        'bhs:routing'
    ),
    (
        'backup_schedule',
        'daily 02:00 UTC'
    ),
    (
        'last_maintenance',
        '2024-01-15'
    );

INSERT INTO
    operators (username, password_hash, role)
VALUES (
        'operator',
        md5('operator123'),
        'operator'
    ),
    (
        'maintenance',
        md5('maint2024'),
        'maintenance'
    ),
    (
        'bhs_service',
        md5('service'),
        'service'
    );