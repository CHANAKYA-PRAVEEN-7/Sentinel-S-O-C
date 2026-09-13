"""
Risk Scoring Engine for SentinelSOC.
Calculates explainable, modular risk scores (0-100) and severity levels
with context-aware explanations and remediation recommendations.
"""
from typing import Dict, List, Tuple, Optional


class RiskEngine:
    """Calculate transparent risk scores, severity classifications, and response recommendations"""
    
    # Base risk scores per threat pattern
    BASE_SCORES = {
        'BRUTE_FORCE': 65,                      # Default: HIGH
        'PASSWORD_SPRAYING': 52,                # Default: MEDIUM, scales with target breadth
        'SUCCESSFUL_LOGIN_AFTER_FAILURES': 82,  # Default: CRITICAL
        'ACCOUNT_ENUMERATION': 45,              # Default: MEDIUM
        'SUSPICIOUS_ACCESS': 55,                # Default: MEDIUM / HIGH
        'UNUSUAL_LOGIN_TIME': 25,               # Default: LOW / MEDIUM
    }
    
    # Baseline event type weights (for individual log lines)
    EVENT_BASE_SCORES = {
        'successful_login': 5,
        'logout': 0,
        'failed_login': 20,
        'invalid_password': 25,
        'invalid_user': 25,
        'account_locked': 50,
        'suspicious_request': 55,
        'access_denied': 45,
        'privilege_escalation': 75,
        'sudo_attempt': 35,
        'ssh_connection': 10,
        'unusual_login_time': 30
    }
    
    @staticmethod
    def calculate_risk_score(threat: Dict) -> int:
        """
        Calculate an explainable risk score (0-100) for a detected threat.
        Considers volume, attack speed, account breadth, and criticality factors.
        """
        threat_type = threat.get('threat_type', '')
        base_score = RiskEngine.BASE_SCORES.get(threat_type, 30)
        
        adjustment = 0
        
        if threat_type == 'BRUTE_FORCE':
            attempts = threat.get('attempt_count', 5)
            # +3 points for each attempt beyond the baseline 5
            adjustment += min(25, (attempts - 5) * 3)
            # Time compression bonus: if condensed in <= 2 minutes
            time_window = threat.get('time_window_minutes', 5.0)
            if time_window <= 2.0:
                adjustment += 10
            elif time_window <= 1.0:
                adjustment += 15
        
        elif threat_type == 'PASSWORD_SPRAYING':
            unique_users = threat.get('unique_user_count', 3)
            # +6 points for each additional account targeted
            adjustment += min(35, (unique_users - 3) * 6)
            total_attempts = threat.get('attempt_count', unique_users)
            if total_attempts > 10:
                adjustment += 10
        
        elif threat_type == 'SUCCESSFUL_LOGIN_AFTER_FAILURES':
            failures = threat.get('failed_attempts', 3)
            # High danger: credential cracking succeeded
            adjustment += min(15, (failures - 3) * 4)
            # If admin/root is compromised, max urgency
            username = str(threat.get('username', '')).lower()
            if username in ('admin', 'administrator', 'root', 'sysadmin'):
                adjustment += 10
        
        elif threat_type == 'ACCOUNT_ENUMERATION':
            users_probed = threat.get('unique_user_count', 4)
            adjustment += min(30, (users_probed - 4) * 5)
        
        elif threat_type == 'SUSPICIOUS_ACCESS':
            denials = threat.get('denial_count', 3)
            adjustment += min(30, (denials - 3) * 6)
        
        elif threat_type == 'UNUSUAL_LOGIN_TIME':
            hour = threat.get('hour', 12)
            # Graveyard shift (00:00 - 05:00) gets higher risk than evening
            if 0 <= hour < 5:
                adjustment += 20
            elif 5 <= hour < 8 or 20 <= hour <= 23:
                adjustment += 10
        
        final_score = max(0, min(100, int(base_score + adjustment)))
        return final_score
    
    @staticmethod
    def get_severity(risk_score: int) -> str:
        """
        Classify risk score into standard severity bands:
        0-29   = LOW
        30-59  = MEDIUM
        60-79  = HIGH
        80-100 = CRITICAL
        """
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def get_severity_badge_class(severity: str) -> str:
        """Map severity to UI badge colors"""
        mapping = {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'LOW': 'secondary'
        }
        return mapping.get(severity, 'secondary')
    
    @staticmethod
    def generate_reason(threat: Dict, risk_score: int) -> str:
        """Generate a concise, human-readable forensic explanation"""
        threat_type = threat.get('threat_type')
        ip = threat.get('source_ip', 'unknown IP')
        
        if threat_type == 'BRUTE_FORCE':
            attempts = threat.get('attempt_count', 0)
            users = ', '.join(threat.get('affected_users', ['unknown'])[:3])
            time_win = threat.get('time_window_minutes', 0)
            return (
                f"{attempts} failed login attempts from IP {ip} targeting '{users}' "
                f"within {time_win} minutes."
            )
        
        elif threat_type == 'PASSWORD_SPRAYING':
            users_count = threat.get('unique_user_count', len(threat.get('affected_users', [])))
            return (
                f"Failed login attempts against {users_count} different user accounts from IP {ip}. "
                f"Behavior matches password spraying pattern."
            )
        
        elif threat_type == 'SUCCESSFUL_LOGIN_AFTER_FAILURES':
            failures = threat.get('failed_attempts', 0)
            username = threat.get('username', 'user')
            time_win = threat.get('time_window_minutes', 5)
            return (
                f"{failures} failed login attempts followed by a successful login for user '{username}' "
                f"from IP {ip} within {time_win} minutes."
            )
        
        elif threat_type == 'ACCOUNT_ENUMERATION':
            count = threat.get('unique_user_count', len(threat.get('affected_users', [])))
            return (
                f"Repeated authentication probes targeting {count} invalid or distinct usernames from IP {ip}. "
                f"Indicates active user enumeration."
            )
        
        elif threat_type == 'SUSPICIOUS_ACCESS':
            count = threat.get('denial_count', 0)
            return (
                f"{count} repeated access denied or privilege escalation attempts from IP {ip}. "
                f"High-risk authorization violations detected."
            )
        
        elif threat_type == 'UNUSUAL_LOGIN_TIME':
            username = threat.get('username', 'unknown')
            hour = threat.get('hour', 0)
            normal = threat.get('normal_hours', '08:00 - 20:00')
            return (
                f"Successful login for user '{username}' from IP {ip} at {hour:02d}:00, "
                f"outside configured normal operating hours ({normal})."
            )
        
        return f"Suspicious security activity detected from IP {ip} (Risk Score: {risk_score})."
    
    @staticmethod
    def generate_recommendation(threat: Dict, risk_score: int) -> str:
        """Generate actionable security remediation advice"""
        threat_type = threat.get('threat_type')
        ip = threat.get('source_ip', 'the source IP')
        severity = RiskEngine.get_severity(risk_score)
        
        if severity == 'CRITICAL':
            action = f"URGENT: Block source IP {ip} at the firewall immediately. "
        elif severity == 'HIGH':
            action = f"Strongly recommend temporarily blocking IP {ip} and notifying the security team. "
        elif severity == 'MEDIUM':
            action = f"Monitor source IP {ip} and apply connection rate-limiting. "
        else:
            action = f"Log and monitor IP {ip} for follow-up activity. "
        
        if threat_type == 'BRUTE_FORCE':
            action += "Enforce multi-factor authentication (MFA) and lock targeted accounts after 5 failed attempts."
        elif threat_type == 'PASSWORD_SPRAYING':
            action += "Prompt password resets for all targeted user accounts and review active sessions."
        elif threat_type == 'SUCCESSFUL_LOGIN_AFTER_FAILURES':
            action += "Immediately revoke active user tokens, force a password reset, and inspect audit logs for unauthorized post-auth actions."
        elif threat_type == 'ACCOUNT_ENUMERATION':
            action += "Ensure authentication responses do not leak account existence (use uniform error messages)."
        elif threat_type == 'SUSPICIOUS_ACCESS':
            action += "Audit endpoint permissions, revoke suspicious API keys, and review sudo privileges."
        elif threat_type == 'UNUSUAL_LOGIN_TIME':
            action += "Contact account owner to verify legitimate after-hours access; check for geographic IP anomalies."
        
        return action
    
    @staticmethod
    def analyze_threat(threat: Dict) -> Dict:
        """Complete threat analysis returning risk score, severity, reason, and recommended response"""
        risk_score = RiskEngine.calculate_risk_score(threat)
        severity = RiskEngine.get_severity(risk_score)
        reason = RiskEngine.generate_reason(threat, risk_score)
        recommendation = RiskEngine.generate_recommendation(threat, risk_score)
        
        return {
            'threat_type': threat.get('threat_type'),
            'risk_score': risk_score,
            'severity': severity,
            'severity_badge': RiskEngine.get_severity_badge_class(severity),
            'reason': reason,
            'recommended_action': recommendation,
            'source_ip': threat.get('source_ip'),
            'affected_users': threat.get('affected_users', []),
            'raw_threat_data': threat
        }
    
    @staticmethod
    def score_single_event(event: Dict) -> Tuple[int, str, Optional[str], Optional[str]]:
        """
        Assign baseline risk score, severity, detected threat, and recommendation to an individual event.
        Returns: (risk_score, severity, detected_threat, recommendation)
        """
        event_type = event.get('event_type', '')
        base_score = RiskEngine.EVENT_BASE_SCORES.get(event_type, 10)
        
        # Off-hours bonus for successful login
        timestamp = event.get('timestamp')
        if event_type == 'successful_login' and timestamp:
            hour = timestamp.hour if hasattr(timestamp, 'hour') else 12
            if hour < 8 or hour >= 20:
                base_score = 35
                severity = 'MEDIUM'
                detected_threat = 'UNUSUAL_LOGIN_TIME'
                recommendation = "Review off-hours login with user."
                return base_score, severity, detected_threat, recommendation
        
        severity = RiskEngine.get_severity(base_score)
        detected_threat = None
        recommendation = None
        
        if event_type == 'privilege_escalation':
            detected_threat = 'PRIVILEGE_ESCALATION_ATTEMPT'
            recommendation = "Investigate unauthorized privilege escalation attempt."
        elif event_type == 'account_locked':
            detected_threat = 'ACCOUNT_LOCKOUT'
            recommendation = "Check for repeated authentication failure causes."
        elif event_type == 'suspicious_request':
            detected_threat = 'SUSPICIOUS_REQUEST'
            recommendation = "Inspect HTTP payload and web application firewall (WAF) logs."
        
        return base_score, severity, detected_threat, recommendation
