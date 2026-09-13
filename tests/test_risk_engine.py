"""
Test suite for SentinelSOC Risk Engine.
Tests risk score calculations, severity thresholds, reason generators, and playbooks.
"""
import pytest
from datetime import datetime, timezone
from detector.risk_engine import RiskEngine


class TestRiskEngine:
    """Validate 0-100 risk scoring and severity classification"""
    
    def test_severity_thresholds(self):
        """Verify severity bands: LOW (0-29), MEDIUM (30-59), HIGH (60-79), CRITICAL (80-100)"""
        # Critical
        assert RiskEngine.get_severity(100) == 'CRITICAL'
        assert RiskEngine.get_severity(85) == 'CRITICAL'
        assert RiskEngine.get_severity(80) == 'CRITICAL'
        
        # High
        assert RiskEngine.get_severity(79) == 'HIGH'
        assert RiskEngine.get_severity(70) == 'HIGH'
        assert RiskEngine.get_severity(60) == 'HIGH'
        
        # Medium
        assert RiskEngine.get_severity(59) == 'MEDIUM'
        assert RiskEngine.get_severity(45) == 'MEDIUM'
        assert RiskEngine.get_severity(30) == 'MEDIUM'
        
        # Low
        assert RiskEngine.get_severity(29) == 'LOW'
        assert RiskEngine.get_severity(15) == 'LOW'
        assert RiskEngine.get_severity(0) == 'LOW'

    def test_brute_force_scoring(self):
        """Test brute force scoring scales with attempt volume and speed"""
        threat_normal = {
            'threat_type': 'BRUTE_FORCE',
            'attempt_count': 5,
            'time_window_minutes': 4.0,
            'source_ip': '198.51.100.45'
        }
        score_normal = RiskEngine.calculate_risk_score(threat_normal)
        assert 60 <= score_normal <= 75
        assert RiskEngine.get_severity(score_normal) == 'HIGH'
        
        # Massive fast attack should escalate to CRITICAL
        threat_heavy = {
            'threat_type': 'BRUTE_FORCE',
            'attempt_count': 14,
            'time_window_minutes': 0.8,
            'source_ip': '198.51.100.45'
        }
        score_heavy = RiskEngine.calculate_risk_score(threat_heavy)
        assert score_heavy >= 80
        assert RiskEngine.get_severity(score_heavy) == 'CRITICAL'

    def test_password_spraying_scoring(self):
        """Test password spraying scoring scales with number of targeted accounts"""
        threat_spray = {
            'threat_type': 'PASSWORD_SPRAYING',
            'unique_user_count': 3,
            'attempt_count': 5,
            'source_ip': '203.0.113.25'
        }
        score = RiskEngine.calculate_risk_score(threat_spray)
        assert 40 <= score <= 60
        
        # Broad campaign across 8 accounts should be HIGH
        threat_broad = {
            'threat_type': 'PASSWORD_SPRAYING',
            'unique_user_count': 8,
            'attempt_count': 15,
            'source_ip': '203.0.113.25'
        }
        score_broad = RiskEngine.calculate_risk_score(threat_broad)
        assert score_broad >= 65
        assert RiskEngine.get_severity(score_broad) in ('HIGH', 'CRITICAL')

    def test_login_after_failures_scoring(self):
        """Test successful login after failures receives high/critical score"""
        threat = {
            'threat_type': 'SUCCESSFUL_LOGIN_AFTER_FAILURES',
            'failed_attempts': 4,
            'username': 'admin',
            'source_ip': '192.168.50.10'
        }
        score = RiskEngine.calculate_risk_score(threat)
        assert score >= 80
        assert RiskEngine.get_severity(score) == 'CRITICAL'

    def test_reason_generation(self):
        """Ensure human-readable reasons describe source IP and attack context"""
        threat = {
            'threat_type': 'BRUTE_FORCE',
            'attempt_count': 12,
            'time_window_minutes': 2.0,
            'source_ip': '192.168.1.50',
            'affected_users': ['admin']
        }
        reason = RiskEngine.generate_reason(threat, 85)
        assert '192.168.1.50' in reason
        assert '12 failed login attempts' in reason

    def test_recommendation_generation(self):
        """Ensure recommendations provide actionable remediation advice"""
        threat = {
            'threat_type': 'SUCCESSFUL_LOGIN_AFTER_FAILURES',
            'source_ip': '10.0.0.5',
            'username': 'john.smith'
        }
        rec = RiskEngine.generate_recommendation(threat, 88)
        assert 'URGENT' in rec or 'Block' in rec
        assert 'password reset' in rec.lower()

    def test_score_single_event(self):
        """Test individual event baseline scoring"""
        score, sev, threat, rec = RiskEngine.score_single_event({
            'event_type': 'failed_login',
            'timestamp': datetime.now(timezone.utc)
        })
        assert score == 20
        assert sev == 'LOW'
        
        score_priv, sev_priv, threat_priv, _ = RiskEngine.score_single_event({
            'event_type': 'privilege_escalation',
            'timestamp': datetime.now(timezone.utc)
        })
        assert score_priv >= 60
        assert sev_priv in ('HIGH', 'CRITICAL')
        assert threat_priv == 'PRIVILEGE_ESCALATION_ATTEMPT'
