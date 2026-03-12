import json
import typing
from datetime import datetime, timezone

if typing.TYPE_CHECKING:
    import sqlite3

PROTOCOL_RARITY = {
    'IRC': 90,
    'Telnet': 85,
    'ICMP': 40,
    'DNS': 20,
    'UDP': 15,
    'TCP': 5
}

def get_protocol_rarity(protocol: str, port: int) -> int:
    # Handle implicit protocols by port if protocol field is just 'TCP' or 'UDP'
    if port == 6667:
        return 90
    if port == 23:
        return 85
    if port == 53 or protocol == 'DNS':
        return 20
    return PROTOCOL_RARITY.get(protocol.upper(), 5)

def evaluate_anomaly(flow: dict, conn: 'sqlite3.Connection') -> float:
    """
    Evaluates statistical anomaly for a flow and updates the IP baseline.
    Returns anomaly_score (0-100 float).
    """
    src_ip = flow['src_ip']
    
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_baselines WHERE ip=?", (src_ip,))
    row = cursor.fetchone()
    
    # Calculate anomaly before updating baseline
    deviation_score = 0.0
    
    if not row:
        # First time seeing this IP, deviation is considered somewhat high but we have no baseline
        # Let's say 50% for unknown
        deviation_score = 50.0
        
        # Insert initial baseline
        cursor.execute('''
            INSERT INTO ip_baselines (ip, total_detections, last_seen, risk_history,
            avg_packet_count, avg_byte_count, avg_duration, sample_count)
            VALUES (?, 0, ?, '[]', ?, ?, ?, 1)
        ''', (src_ip, flow['timestamp'], flow['packet_count'], flow['byte_count'], flow['duration']))
    else:
        n = row['sample_count']
        if n == 0:
            n = 1 # Avoid division by zero
            
        old_avg_pkt = row['avg_packet_count']
        old_avg_byte = row['avg_byte_count']
        old_avg_dur = row['avg_duration']
        
        # Calculate deviation percentage from baseline (capped at 100%)
        def calc_dev(val, avg):
            if avg == 0: return 100.0 if val > 0 else 0.0
            dev = abs(val - avg) / avg * 100.0
            return min(100.0, dev)
            
        dev_pkt = calc_dev(flow['packet_count'], old_avg_pkt)
        dev_byte = calc_dev(flow['byte_count'], old_avg_byte)
        dev_dur = calc_dev(flow['duration'], old_avg_dur)
        
        # Deviation score: packet count 40%, byte count 40%, duration 20%
        deviation_score = (dev_pkt * 0.4) + (dev_byte * 0.4) + (dev_dur * 0.2)
        
        # Rolling average update: new_avg = (old_avg * n + new_val) / (n+1)
        new_n = n + 1
        new_avg_pkt = (old_avg_pkt * n + flow['packet_count']) / new_n
        new_avg_byte = (old_avg_byte * n + flow['byte_count']) / new_n
        new_avg_dur = (old_avg_dur * n + flow['duration']) / new_n
        
        cursor.execute('''
            UPDATE ip_baselines
            SET avg_packet_count=?, avg_byte_count=?, avg_duration=?, sample_count=?, last_seen=?
            WHERE ip=?
        ''', (new_avg_pkt, new_avg_byte, new_avg_dur, new_n, flow['timestamp'], src_ip))

    rarity = float(get_protocol_rarity(flow['protocol'], flow['port']))
    
    # anomaly_score = 0.6 × deviation + 0.4 × rarity (capped 100)
    anomaly_score = (0.6 * deviation_score) + (0.4 * rarity)
    
    return min(100.0, anomaly_score)

def update_ip_risk_history(ip: str, new_risk: float, conn: 'sqlite3.Connection'):
    cursor = conn.cursor()
    cursor.execute("SELECT risk_history, total_detections FROM ip_baselines WHERE ip=?", (ip,))
    row = cursor.fetchone()
    if not row:
        return
        
    try:
        history = json.loads(row['risk_history'])
    except:
        history = []
        
    history.append(new_risk)
    if len(history) > 10:
        history = history[-10:]
        
    total_det = row['total_detections'] + 1
    
    cursor.execute('''
        UPDATE ip_baselines
        SET risk_history=?, total_detections=?
        WHERE ip=?
    ''', (json.dumps(history), total_det, ip))
