PRAGMA foreign_keys = ON;

-- All system events.
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    rule_id TEXT,
    severity TEXT,
    message TEXT,
    details TEXT
);


-- Every blocking incident.
-- R1 and R2 incidents are stored here.
-- R3 flag events are stored only in events.
CREATE TABLE IF NOT EXISTS blocking_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    offence_count INTEGER NOT NULL,
    ban_duration_seconds INTEGER NOT NULL,
    timestamp REAL NOT NULL
);


-- Hosts that are currently blocked.
CREATE TABLE IF NOT EXISTS active_bans (
    source_ip TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    offence_count INTEGER NOT NULL,
    start_time REAL NOT NULL,
    expiry_time REAL NOT NULL,
    cookie INTEGER NOT NULL
);


-- Useful indexes for dashboard queries.
CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_source_ip
ON events(source_ip);

CREATE INDEX IF NOT EXISTS idx_events_type
ON events(event_type);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip
ON blocking_incidents(source_ip);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp
ON blocking_incidents(timestamp);

CREATE INDEX IF NOT EXISTS idx_bans_expiry
ON active_bans(expiry_time);
