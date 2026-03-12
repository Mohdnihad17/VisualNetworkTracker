from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
import json

@dataclass
class TrafficFlow:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    packet_count: int
    byte_count: int
    duration: float
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class Detection:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    alert_type: str
    rule_score: float
    anomaly_score: float
    final_score: float
    severity: str
    confidence: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_url: str
    # Store these JSON strings in DB, but parse for to_dict
    analyst_context: str
    simple_context: str
    status: str = "Open"
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        try:
            d['analyst_context'] = json.loads(self.analyst_context) if self.analyst_context else {}
        except Exception:
            pass
        try:
            d['simple_context'] = json.loads(self.simple_context) if self.simple_context else {}
        except Exception:
            pass
        return d

@dataclass
class AnalystAction:
    detection_id: int
    action: str
    timestamp: str
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class SimulatedAttack:
    attack_type: str
    status: str
    start_time: str
    end_time: str
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
