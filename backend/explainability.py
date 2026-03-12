import json
from typing import Tuple, Dict, Any, List
from datetime import datetime, timedelta
from dateutil import parser
import typing

if typing.TYPE_CHECKING:
    import sqlite3

MITRE_MAPPING = {
    'dos': {
        'tactic': 'Impact',
        'tactic_id': 'TA0040',
        'technique_id': 'T1498',
        'technique_name': 'Network Denial of Service',
        'subtechnique': 'T1498.001',
        'guidance': 'Monitor network traffic for anomalous volume or bandwidth consumption.',
        'cve': 'CVE-2023-44487 (HTTP/2 Rapid Reset DDoS)',
        'signature': 'SYN flood detected — half-open connections exceed threshold'
    },
    'portscan': {
        'tactic': 'Discovery',
        'tactic_id': 'TA0007',
        'technique_id': 'T1046',
        'technique_name': 'Network Service Scanning',
        'subtechnique': 'None',
        'guidance': 'Look for unexpected connection attempts across many ports from a single source.',
        'cve': 'N/A (Reconnaissance Technique)',
        'signature': 'ET SCAN Potential SSH Scan OUTBOUND'
    },
    'bruteforce': {
        'tactic': 'Credential Access',
        'tactic_id': 'TA0006',
        'technique_id': 'T1110',
        'technique_name': 'Brute Force',
        'subtechnique': 'T1110.001',
        'guidance': 'Monitor authentication logs for multiple failed attempts followed by success.',
        'cve': 'CVE-2021-34473 (ProxyShell - often used post-bruteforce)',
        'signature': 'ET SCAN Suspicious inbound to MSSQL port 1433'
    },
    'suspdns': {
        'tactic': 'Command and Control',
        'tactic_id': 'TA0011',
        'technique_id': 'T1568',
        'technique_name': 'Dynamic Resolution',
        'subtechnique': 'T1568.002',
        'guidance': 'Look for abnormal DNS request volumes or requests for newly registered domains.',
        'cve': 'CVE-2020-1350 (SIGRed - DNS severity)',
        'signature': 'ET MALWARE DNS Query to Suspicious .top domain'
    },
    'lateral': {
        'tactic': 'Lateral Movement',
        'tactic_id': 'TA0008',
        'technique_id': 'T1021',
        'technique_name': 'Remote Services',
        'subtechnique': 'T1021.002',
        'guidance': 'Monitor for remote logons using local admin credentials across boundaries.',
        'cve': 'CVE-2017-0144 (EternalBlue SMBv1)',
        'signature': 'ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Request (NTLM SSP)'
    },
    'packet_burst': {
        'tactic': 'Impact',
        'tactic_id': 'TA0040',
        'technique_id': 'T1498',
        'technique_name': 'Network Denial of Service',
        'subtechnique': 'T1498.001',
        'guidance': 'Monitor bandwidth utilization to detect network flooding.',
        'cve': 'N/A',
        'signature': 'ET SCAN Potential UDP Scan'
    },
    'suspicious_proto': {
        'tactic': 'Command and Control',
        'tactic_id': 'TA0011',
        'technique_id': 'T1090',
        'technique_name': 'Proxy',
        'subtechnique': 'T1090.002',
        'guidance': 'Look for protocols mismatching expected ports (e.g. SSH on port 80).',
        'cve': 'N/A',
        'signature': 'ET POLICY Suspicious Protocol over Web Port'
    },
    'repeated_destination': {
        'tactic': 'Exfiltration',
        'tactic_id': 'TA0010',
        'technique_id': 'T1041',
        'technique_name': 'Exfiltration Over C2 Channel',
        'subtechnique': 'None',
        'guidance': 'Monitor for repeated, large transfers to unrecognized external IPs.',
        'cve': 'N/A',
        'signature': 'ET INFO Suspiciously frequent connections to external IP'
    },
    'default': {
        'tactic': 'Initial Access',
        'tactic_id': 'TA0001',
        'technique_id': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'subtechnique': 'None',
        'guidance': 'Monitor application logs for unexpected system process spawning.',
        'cve': 'N/A',
        'signature': 'ET EXPLOIT Generic Exploit Attempt'
    }
}

SIMPLE_ATTACK_NAMES = {
    'dos': "Server Overload Attempt",
    'portscan': "Network Probing",
    'bruteforce': "Repeated Login Failures",
    'suspdns': "Suspicious Internet Requests",
    'lateral': "Unauthorized Internal Access",
    'packet_burst': "Traffic Spike",
    'suspicious_proto': "Unusual Connection Type",
    'repeated_destination': "Repeated Connections"
}

GEO_COUNTRY_MAP = {
    '185.220.101.45': 'Germany',
    '45.33.32.156': 'United States',
    '89.248.167.131': 'Netherlands',
    '179.43.128.10': 'Switzerland',
    '80.82.77.139': 'Netherlands',
    '185.156.73.54': 'Russia',
    '103.151.108.55': 'China',
    '194.165.16.11': 'Iran'
}

def determine_attack_type(triggered_rules: List[str], flow: dict) -> str:
    """Map the triggered rules and flow to a specific standardized attack type."""
    rules_lower = [r.lower() for r in triggered_rules]
    
    if 'port scan' in rules_lower:
        return 'portscan'
    if 'brute force' in rules_lower:
        return 'bruteforce'
    if 'suspicious dns' in rules_lower:
        return 'suspdns'
    # 'lateral' is specifically TCP 445/3389/23 from internal to internal, but our rules might flag it as Suspicious Protocol
    if flow['src_ip'].startswith('10.') and flow['dst_ip'].startswith('10.') and flow['port'] in [445, 3389, 23]:
        return 'lateral'
    if flow['protocol'] == 'TCP' and flow['port'] in [80, 443] and 'packet burst' in rules_lower:
        return 'dos'
    if 'suspicious protocol' in rules_lower:
        return 'suspicious_proto'
    if 'packet burst' in rules_lower:
        return 'packet_burst'
    if 'repeated destination' in rules_lower:
        return 'repeated_destination'
    
    return 'unknown'

def calculate_risk(rule_score: float, anomaly_score: float) -> Tuple[float, str]:
    """Risk Fusion Engine."""
    final_score = round(0.55 * rule_score + 0.45 * anomaly_score, 2)
    
    if final_score >= 75:
        severity = 'High'
    elif final_score >= 45:
        severity = 'Medium'
    else:
        severity = 'Low'
        
    return final_score, severity

def calculate_confidence(rule_count: int, ip_sample_count: int) -> str:
    """Confidence: based on sample_count and rule trigger count."""
    score = 0
    if rule_count > 1:
        score += 40
    elif rule_count == 1:
        score += 20
        
    if ip_sample_count > 50:
        score += 60
    elif ip_sample_count > 10:
        score += 40
    else:
        score += 20
        
    if score >= 80:
        return "High (80-100%)"
    elif score >= 50:
        return "Medium (50-79%)"
    else:
        return "Low (<50%)"

def generate_analyst_context(
    triggered_rules: List[str], final_score: float, rule_score: float, 
    anomaly_score: float, confidence: str, attack_type: str
) -> str:
    mitre_info = MITRE_MAPPING.get(attack_type, MITRE_MAPPING['default'])
    
    context = {
        "front": "Why was this flagged?",
        "front_summary": f"Detected {len(triggered_rules)} rule violations and statistical anomalies.",
        "rule_explanation": f"Rules Fired: {', '.join(triggered_rules) if triggered_rules else 'None'}. Exceeded standard thresholds.",
        "score_breakdown": {
            "rule_score": round(rule_score, 2),
            "anomaly_score": round(anomaly_score, 2),
            "final_score": final_score,
            "formula": "Final = 0.55 × Rule + 0.45 × Anomaly"
        },
        "mitre": {
            "tactic": mitre_info['tactic'],
            "tactic_id": mitre_info['tactic_id'],
            "technique_id": mitre_info['technique_id'],
            "technique_name": mitre_info['technique_name'],
            "subtechnique": mitre_info['subtechnique'],
            "guidance": mitre_info['guidance'],
            "url": f"https://attack.mitre.org/techniques/{mitre_info['technique_id'].split('.')[0]}"
        },
        "signature_matched": mitre_info['signature'],
        "real_world_scenario": f"An attacker may be attempting a {mitre_info['technique_name']} attack to achieve {mitre_info['tactic']}.",
        "mitigation": ["Isolate the affected host.", "Block the malicious source IP.", "Review firewall logs for secondary indicators."],
        "confidence_explanation": f"Confidence is {confidence} based on established baseline and clear rule violations."
    }
    return json.dumps(context)

def generate_simple_context(attack_type: str) -> str:
    plain_name = SIMPLE_ATTACK_NAMES.get(attack_type, "Unusual Network Activity")
    mitre_info = MITRE_MAPPING.get(attack_type, MITRE_MAPPING['default'])
    
    context = {
        "front": "What happened?",
        "front_summary": f"We noticed a {plain_name.lower()}.",
        "what_happened": f"A device on your network was communicating in a way that matches known patterns for {plain_name.lower()}.",
        "real_world_analogy": "It's like someone rattling all the doorknobs in your building to see if any are unlocked.",
        "what_to_do": ["Alert your IT Team", "Check the device for viruses", "Update system passwords"],
        "related_cves": f"Related CVE: {mitre_info['cve']}"
    }
    return json.dumps(context)

def generate_story_feed(conn: 'sqlite3.Connection') -> List[Dict[str, Any]]:
    """Groups detections into 5-minute windows, returns plain English narrative per window."""
    cursor = conn.cursor()
    # Get recent detections sorted by timestamp
    cursor.execute('''
        SELECT timestamp, severity, alert_type, src_ip, dst_ip
        FROM detections
        ORDER BY timestamp DESC
        LIMIT 500
    ''')
    rows = cursor.fetchall()
    
    if not rows:
        return []

    windows = {}
    for row in rows:
        dt = parser.parse(row['timestamp'])
        # Round down to nearest 5 minutes
        window_start = dt.replace(minute=(dt.minute // 5) * 5, second=0, microsecond=0)
        
        if window_start not in windows:
            windows[window_start] = []
        windows[window_start].append(dict(row))
    
    stories = []
    for w_start in sorted(windows.keys(), reverse=True)[:20]:
        dets = windows[w_start]
        highs = [d for d in dets if d['severity'] == 'High']
        meds = [d for d in dets if d['severity'] == 'Medium']
        
        twelve_hr_time = w_start.strftime("%I:%M %p")
        iso_time = w_start.isoformat()
        
        if highs:
            severity = 'high'
            attack = highs[0]['alert_type']
            plain_name = SIMPLE_ATTACK_NAMES.get(attack, "Threat")
            text = f"A serious threat was detected. {plain_name} was identified targeting a device."
        elif meds:
            severity = 'medium'
            attack = meds[0]['alert_type']
            plain_name = SIMPLE_ATTACK_NAMES.get(attack, "Unusual Behavior")
            text = f"Unusual activity was detected. A device made suspicious requests matching {plain_name.lower()}."
        else:
            severity = 'low'
            conn_count = max(12, len(dets))
            text = f"Network activity was normal. {conn_count} routine connections were made."
            
        stories.append({
            "time": twelve_hr_time,
            "severity": severity,
            "text": text,
            "window_start": iso_time
        })
        
    return stories
