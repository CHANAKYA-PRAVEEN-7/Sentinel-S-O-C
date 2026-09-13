"""
Threat detector orchestrator for SentinelSOC.
Coordinates all detection rules and enriches results with risk scoring.
"""
from typing import List, Dict
from detector.rules import ThreatRules
from detector.risk_engine import RiskEngine


class ThreatDetector:
    """Orchestrate rule evaluations and risk assessments across security event sets"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.detected_threats: List[Dict] = []
    
    def detect_all_threats(self, events: List[Dict]) -> List[Dict]:
        """
        Run all detection rules against the provided events list and return analyzed threats.
        """
        if not events:
            return []
        
        all_threats = []
        
        # Rule A: Brute Force
        bf_cfg = self.config.get('brute_force', {})
        threats = ThreatRules.detect_brute_force(
            events,
            threshold=bf_cfg.get('failed_attempts', 5),
            time_window_minutes=bf_cfg.get('time_window_minutes', 5)
        )
        all_threats.extend(threats)
        
        # Rule B: Password Spraying
        spray_cfg = self.config.get('password_spraying', {})
        threats = ThreatRules.detect_password_spraying(
            events,
            unique_user_threshold=spray_cfg.get('unique_users', 3),
            time_window_minutes=spray_cfg.get('time_window_minutes', 10)
        )
        all_threats.extend(threats)
        
        # Rule C: Successful Login After Multiple Failures
        login_cfg = self.config.get('login_after_failures', {})
        threats = ThreatRules.detect_successful_login_after_failures(
            events,
            failure_threshold=login_cfg.get('failed_attempts', 3),
            time_window_minutes=login_cfg.get('time_window_minutes', 5)
        )
        all_threats.extend(threats)
        
        # Rule D: Account Enumeration
        enum_cfg = self.config.get('account_enumeration', {})
        threats = ThreatRules.detect_account_enumeration(
            events,
            unique_user_threshold=enum_cfg.get('unique_users', 4),
            time_window_minutes=enum_cfg.get('time_window_minutes', 15)
        )
        all_threats.extend(threats)
        
        # Rule E: Suspicious Access
        access_cfg = self.config.get('suspicious_access', {})
        threats = ThreatRules.detect_suspicious_access(
            events,
            access_denied_threshold=access_cfg.get('access_denied_threshold', 3),
            time_window_minutes=access_cfg.get('time_window_minutes', 10)
        )
        all_threats.extend(threats)
        
        # Rule F: Unusual Login Time
        unusual_cfg = self.config.get('unusual_login', {})
        threats = ThreatRules.detect_unusual_login_time(
            events,
            normal_start_hour=unusual_cfg.get('normal_hours_start', 8),
            normal_end_hour=unusual_cfg.get('normal_hours_end', 20)
        )
        all_threats.extend(threats)
        
        # Analyze each threat with the Risk Engine
        analyzed_threats = []
        for threat in all_threats:
            analysis = RiskEngine.analyze_threat(threat)
            analyzed_threats.append(analysis)
        
        # Sort threats by risk score descending
        analyzed_threats.sort(key=lambda x: x['risk_score'], reverse=True)
        self.detected_threats = analyzed_threats
        
        return analyzed_threats
    
    def get_critical_threats(self) -> List[Dict]:
        return [t for t in self.detected_threats if t['severity'] == 'CRITICAL']
    
    def get_high_threats(self) -> List[Dict]:
        return [t for t in self.detected_threats if t['severity'] == 'HIGH']
    
    def get_threat_summary(self) -> Dict:
        total = len(self.detected_threats)
        critical = len(self.get_critical_threats())
        high = len(self.get_high_threats())
        medium = len([t for t in self.detected_threats if t['severity'] == 'MEDIUM'])
        low = len([t for t in self.detected_threats if t['severity'] == 'LOW'])
        
        threat_types = {}
        for threat in self.detected_threats:
            t_type = threat.get('threat_type', 'unknown')
            threat_types[t_type] = threat_types.get(t_type, 0) + 1
        
        avg_score = (sum(t['risk_score'] for t in self.detected_threats) / total) if total > 0 else 0
        
        return {
            'total_threats': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'threat_types': threat_types,
            'avg_risk_score': round(avg_score, 2)
        }
