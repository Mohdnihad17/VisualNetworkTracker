import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')

def get_connection():
    """Returns a SQLite connection with Row factory."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initializes the database creating all tables if they don't exist."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # traffic_flows
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            packet_count INTEGER NOT NULL,
            byte_count INTEGER NOT NULL,
            duration REAL NOT NULL,
            processed INTEGER DEFAULT 0
        )
        ''')
        
        # Patch existing databases with missing column
        try:
            cursor.execute("ALTER TABLE traffic_flows ADD COLUMN processed INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        
        # detections
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            rule_score REAL NOT NULL,
            anomaly_score REAL NOT NULL,
            final_score REAL NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            mitre_tactic TEXT NOT NULL,
            mitre_technique_id TEXT NOT NULL,
            mitre_technique_name TEXT NOT NULL,
            mitre_url TEXT NOT NULL,
            analyst_context TEXT NOT NULL,
            simple_context TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open'
        )
        ''')
        
        # Indexes for detections
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections (timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections (severity)')
        
        # analyst_actions
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analyst_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(detection_id) REFERENCES detections(id)
        )
        ''')
        
        # ip_baselines
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_baselines (
            ip TEXT PRIMARY KEY,
            total_detections INTEGER DEFAULT 0,
            last_seen TEXT,
            risk_history TEXT DEFAULT '[]',
            avg_packet_count REAL DEFAULT 0.0,
            avg_byte_count REAL DEFAULT 0.0,
            avg_duration REAL DEFAULT 0.0,
            sample_count INTEGER DEFAULT 0
        )
        ''')
        
        # simulated_attacks
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS simulated_attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            status TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT
        )
        ''')
        
        # simulation_debriefs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS simulation_debriefs (
            simulation_id INTEGER PRIMARY KEY,
            attack_type TEXT NOT NULL,
            attack_name TEXT NOT NULL,
            total_alerts INTEGER NOT NULL,
            first_detection_seconds REAL NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            detection_grade TEXT NOT NULL,
            what_happened TEXT NOT NULL,
            real_world_impact TEXT NOT NULL,
            protection_steps TEXT NOT NULL,
            FOREIGN KEY(simulation_id) REFERENCES simulated_attacks(id)
        )
        ''')
