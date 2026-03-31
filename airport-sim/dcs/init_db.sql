-- ============================================================
-- DCS Database Schema
-- Central hub for airport IT simulation
-- ============================================================

-- Flights table
-- FIDS subscribes to real-time updates on gate, status, estimated_time
CREATE TABLE flights (
    id SERIAL PRIMARY KEY,
    flight_number VARCHAR(10) UNIQUE NOT NULL,
    airline VARCHAR(100) NOT NULL,
    origin VARCHAR(5) NOT NULL,
    destination VARCHAR(5) NOT NULL,
    scheduled_departure TIMESTAMP NOT NULL,
    estimated_departure TIMESTAMP,
    gate VARCHAR(10),
    status VARCHAR(20) DEFAULT 'scheduled',
    aircraft_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Passengers table: PII - subject to UK GDPR Article 32
-- VULNERABILITY: PII stored in plaintext, no encryption at rest
CREATE TABLE passengers (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    passport_number VARCHAR(20) UNIQUE NOT NULL,
    nationality VARCHAR(100),
    date_of_birth DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bookings table: links passengers to flights
-- Written to by Online Booking System, read by DCS for check-in
CREATE TABLE bookings (
    id SERIAL PRIMARY KEY,
    reference VARCHAR(8) UNIQUE NOT NULL,
    passenger_id INTEGER REFERENCES passengers (id),
    flight_id INTEGER REFERENCES flights (id),
    seat_number VARCHAR(5), -- assigned at check-in
    travel_class VARCHAR(20) DEFAULT 'economy',
    booking_status VARCHAR(20) DEFAULT 'confirmed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Boarding passes table: generated at check-in by DCS
-- VULNERABILITY: JWT-based passes susceptible to algorithm confusion
CREATE TABLE boarding_passes (
    id SERIAL PRIMARY KEY,
    booking_id INTEGER REFERENCES bookings (id),
    passenger_id INTEGER REFERENCES passengers (id),
    flight_id INTEGER REFERENCES flights (id),
    seat_number VARCHAR(5) NOT NULL,
    boarding_group VARCHAR(5),
    barcode_data TEXT,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Baggage table: tracked by BHS, created at check-in
-- Contains passenger-to-bag linkages (PII under UK GDPR)
CREATE TABLE baggage (
    id SERIAL PRIMARY KEY,
    tag_id VARCHAR(20) UNIQUE NOT NULL,
    passenger_id INTEGER REFERENCES passengers (id),
    flight_id INTEGER REFERENCES flights (id),
    booking_id INTEGER REFERENCES bookings (id),
    weight_kg DECIMAL(5, 2),
    status VARCHAR(20) DEFAULT 'checked_in',
    current_location VARCHAR(50) DEFAULT 'check-in',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Staff/operators table for DCS access
-- VULNERABILITY: no role separation between operator and admin
-- VULNERABILITY: weak password hashing, md5 instead of bcrypt
CREATE TABLE staff (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(200),
    role VARCHAR(20) DEFAULT 'operator',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- SEED DATA: UK airport flights and passengers
-- ============================================================

-- Flights next 24 hours from Heathrow
INSERT INTO
    flights (
        flight_number,
        airline,
        origin,
        destination,
        scheduled_departure,
        estimated_departure,
        gate,
        status,
        aircraft_type
    )
VALUES (
        'BA0117',
        'British Airways',
        'LHR',
        'JFK',
        NOW() + INTERVAL '2 hours',
        NOW() + INTERVAL '2 hours',
        'A14',
        'scheduled',
        'Boeing 777-300ER'
    ),
    (
        'BA0303',
        'British Airways',
        'LHR',
        'CDG',
        NOW() + INTERVAL '3 hours',
        NOW() + INTERVAL '3 hours',
        'B7',
        'scheduled',
        'Airbus A320'
    ),
    (
        'VS0401',
        'Virgin Atlantic',
        'LHR',
        'LAX',
        NOW() + INTERVAL '4 hours',
        NOW() + INTERVAL '4 hours',
        'A22',
        'scheduled',
        'Airbus A350-1000'
    ),
    (
        'EK0007',
        'Emirates',
        'LHR',
        'DXB',
        NOW() + INTERVAL '5 hours',
        NOW() + INTERVAL '5 hours 15 minutes',
        NULL,
        'delayed',
        'Airbus A380'
    ),
    (
        'LH0901',
        'Lufthansa',
        'LHR',
        'FRA',
        NOW() + INTERVAL '1 hour',
        NOW() + INTERVAL '1 hour',
        'C3',
        'boarding',
        'Airbus A321'
    ),
    (
        'AF1081',
        'Air France',
        'LHR',
        'CDG',
        NOW() + INTERVAL '6 hours',
        NOW() + INTERVAL '6 hours',
        NULL,
        'scheduled',
        'Airbus A320'
    ),
    (
        'UA0919',
        'United Airlines',
        'LHR',
        'EWR',
        NOW() + INTERVAL '7 hours',
        NOW() + INTERVAL '7 hours',
        NULL,
        'scheduled',
        'Boeing 767-300'
    ),
    (
        'BA0853',
        'British Airways',
        'LHR',
        'BER',
        NOW() + INTERVAL '8 hours',
        NOW() + INTERVAL '8 hours',
        NULL,
        'scheduled',
        'Airbus A320neo'
    );

-- Passengers (synthetic PII - GDPR compliant for simulation)
INSERT INTO
    passengers (
        first_name,
        last_name,
        email,
        passport_number,
        nationality,
        date_of_birth
    )
VALUES (
        'James',
        'Wilson',
        'j.wilson@email.com',
        'GB123456789',
        'British',
        '1985-03-14'
    ),
    (
        'Sarah',
        'Chen',
        's.chen@email.com',
        'GB987654321',
        'British',
        '1990-07-22'
    ),
    (
        'Ahmed',
        'Hassan',
        'a.hassan@email.com',
        'GB456789123',
        'British',
        '1978-11-05'
    ),
    (
        'Maria',
        'Garcia',
        'm.garcia@email.com',
        'ES112233445',
        'Spanish',
        '1995-01-30'
    ),
    (
        'Thomas',
        'Mueller',
        't.mueller@email.com',
        'DE998877665',
        'German',
        '1982-09-18'
    ),
    (
        'Yuki',
        'Tanaka',
        'y.tanaka@email.com',
        'JP554433221',
        'Japanese',
        '1993-04-12'
    ),
    (
        'Olivia',
        'Brown',
        'o.brown@email.com',
        'GB111222333',
        'British',
        '1988-12-25'
    ),
    (
        'David',
        'Okonkwo',
        'd.okonkwo@email.com',
        'NG445566778',
        'Nigerian',
        '1975-06-08'
    ),
    (
        'Emma',
        'Johnson',
        'e.johnson@email.com',
        'GB333444555',
        'British',
        '2001-02-14'
    ),
    (
        'Lucas',
        'Dubois',
        'l.dubois@email.com',
        'FR667788990',
        'French',
        '1997-08-03'
    ),
    (
        'Priya',
        'Patel',
        'p.patel@email.com',
        'GB778899001',
        'British',
        '1986-10-20'
    ),
    (
        'Chen',
        'Wei',
        'c.wei@email.com',
        'CN889900112',
        'Chinese',
        '1991-05-15'
    );

-- Bookings
INSERT INTO
    bookings (
        reference,
        passenger_id,
        flight_id,
        seat_number,
        travel_class,
        booking_status
    )
VALUES (
        'ABCD1234',
        1,
        1,
        NULL,
        'business',
        'confirmed'
    ),
    (
        'EFGH5678',
        2,
        1,
        NULL,
        'economy',
        'confirmed'
    ),
    (
        'IJKL9012',
        3,
        2,
        NULL,
        'economy',
        'confirmed'
    ),
    (
        'MNOP3456',
        4,
        3,
        NULL,
        'economy',
        'confirmed'
    ),
    (
        'QRST7890',
        5,
        4,
        NULL,
        'business',
        'confirmed'
    ),
    (
        'UVWX1234',
        6,
        5,
        '12A',
        'economy',
        'checked_in'
    ),
    (
        'YZAB5678',
        7,
        5,
        '14C',
        'economy',
        'checked_in'
    ),
    (
        'CDEF9012',
        8,
        1,
        NULL,
        'first',
        'confirmed'
    ),
    (
        'GHIJ3456',
        9,
        3,
        NULL,
        'economy',
        'confirmed'
    ),
    (
        'KLMN7890',
        10,
        2,
        NULL,
        'business',
        'confirmed'
    ),
    (
        'OPQR1234',
        11,
        4,
        NULL,
        'economy',
        'confirmed'
    ),
    (
        'STUV5678',
        12,
        6,
        NULL,
        'economy',
        'confirmed'
    );

-- Already checked-in passengers get boarding passes and baggage
INSERT INTO
    boarding_passes (
        booking_id,
        passenger_id,
        flight_id,
        seat_number,
        boarding_group,
        barcode_data
    )
VALUES (
        6,
        6,
        5,
        '12A',
        'B',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder_token_1'
    ),
    (
        7,
        7,
        5,
        '14C',
        'C',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder_token_2'
    );

INSERT INTO
    baggage (
        tag_id,
        passenger_id,
        flight_id,
        booking_id,
        weight_kg,
        status,
        current_location
    )
VALUES (
        'LHR-LH0901-001',
        6,
        5,
        6,
        18.5,
        'security_cleared',
        'screening'
    ),
    (
        'LHR-LH0901-002',
        7,
        5,
        7,
        23.0,
        'security_cleared',
        'screening'
    ),
    (
        'LHR-LH0901-003',
        7,
        5,
        7,
        12.2,
        'security_cleared',
        'screening'
    );

-- Staff accounts
-- VULNERABILITY: md5 hashing, weak passwords, no role separation enforced
INSERT INTO
    staff (
        username,
        password_hash,
        full_name,
        role
    )
VALUES (
        'admin',
        md5('admin123'),
        'System Administrator',
        'admin'
    ),
    (
        'operator',
        md5('operator1'),
        'Check-in Operator',
        'operator'
    ),
    (
        'kiosk01',
        md5('kiosk2024'),
        'Self-Service Kiosk 1',
        'kiosk'
    ),
    (
        'kiosk02',
        md5('kiosk2024'),
        'Self-Service Kiosk 2',
        'kiosk'
    );