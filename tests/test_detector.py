"""
Test suite for SentinelSOC Log Parser and Threat Detector.
Validates log parsing, rule detection heuristics, and orchestrator execution.
"""
import pytest
from datetime import datetime, timedelta
from detector import LogParser, ThreatDetector, RiskEngine
from detector.rules import ThreatRules


class TestLogParser:
    """Test log line parsing and regex extraction"""
    
    def test_parse_valid_line(self):
        parser = LogParser()
        line = "2026-09-14 08:15:23 INFO LOGIN_SUCCESS username=john.smith ip=192.168.1.100"
        event = parser.parse_line(line)
        
        assert event is not None
        assert event['event_type'] == 'successful_login'
        assert event['username'] == 'john.smith'
        assert event['source_ip'] == '192.168.1.100'
        assert event['timestamp'].hour == 8
    
    def test_parse_invalid_line(self):
        parser = LogParser()
        line = "Malformed log line without timestamp"
        event = parser.parse_line(line)
        assert event is None
    
    def test_parse_multiple_lines(self):
        parser = LogParser()
        content = (
            "2026-09-14 08:15:23 INFO LOGIN_SUCCESS username=john.smith ip=192.168.1.100\n"
            "2026-09-14 08:16:45 INFO LOGIN_FAILED username=admin ip=192.168.50.10 message=bad_pwd\n"
            "2026-09-14 08:17:10 INFO ACCESS_DENIED username=hacker ip=10.0.0.1\n"
        )
        events = parser.parse_string(content)
        assert len(events) == 3
        assert events[0]['event_type'] == 'successful_login'
        assert events[1]['event_type'] == 'failed_login'
        assert events[2]['event_type'] == 'access_denied'


class TestThreatDetectionRules:
    """Test individual heuristic threat detection rules"""
    
    def test_brute_force_detection(self):
        base_time = datetime(2026, 9, 14, 10, 0, 0)
        events = []
        for i in range(6):
            events.append({
                'timestamp': base_time + timedelta(seconds=i * 5),
                'event_type': 'failed_login',
                'username': 'admin',
                'source_ip': '198.51.100.45'
            })
            
        threats = ThreatRules.detect_brute_force(events, threshold=5, time_window_minutes=5)
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'BRUTE_FORCE'
        assert threats[0]['source_ip'] == '198.51.100.45'
        assert threats[0]['attempt_count'] == 6
    
    def test_password_spraying_detection(self):
        base_time = datetime(2026, 9, 14, 11, 0, 0)
        users = ['admin', 'alice', 'bob', 'charlie', 'david']
        events = []
        for i, u in enumerate(users):
            events.append({
                'timestamp': base_time + timedelta(seconds=i * 10),
                'event_type': 'failed_login',
                'username': u,
                'source_ip': '203.0.113.88'
            })
            
        threats = ThreatRules.detect_password_spraying(events, unique_user_threshold=3, time_window_minutes=10)
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'PASSWORD_SPRAYING'
        assert threats[0]['unique_user_count'] == 5
        assert threats[0]['source_ip'] == '203.0.113.88'

    def test_login_after_failures_detection(self):
        base_time = datetime(2026, 9, 14, 12, 0, 0)
        events = [
            {'timestamp': base_time, 'event_type': 'failed_login', 'username': 'admin', 'source_ip': '192.168.50.10'},
            {'timestamp': base_time + timedelta(seconds=10), 'event_type': 'failed_login', 'username': 'admin', 'source_ip': '192.168.50.10'},
            {'timestamp': base_time + timedelta(seconds=20), 'event_type': 'failed_login', 'username': 'admin', 'source_ip': '192.168.50.10'},
            {'timestamp': base_time + timedelta(seconds=30), 'event_type': 'successful_login', 'username': 'admin', 'source_ip': '192.168.50.10'},
        ]
        threats = ThreatRules.detect_successful_login_after_failures(events, failure_threshold=3, time_window_minutes=5)
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'SUCCESSFUL_LOGIN_AFTER_FAILURES'
        assert threats[0]['username'] == 'admin'

    def test_account_enumeration_detection(self):
        base_time = datetime(2026, 9, 14, 13, 0, 0)
        invalid_users = ['ghost1', 'ghost2', 'ghost3', 'ghost4', 'ghost5']
        events = []
        for i, u in enumerate(invalid_users):
            events.append({
                'timestamp': base_time + timedelta(seconds=i * 4),
                'event_type': 'invalid_user',
                'username': u,
                'source_ip': '203.0.113.199'
            })
            
        threats = ThreatRules.detect_account_enumeration(events, unique_user_threshold=4, time_window_minutes=15)
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'ACCOUNT_ENUMERATION'
        assert threats[0]['unique_user_count'] == 5

    def test_suspicious_access_detection(self):
        base_time = datetime(2026, 9, 14, 14, 0, 0)
        events = [
            {'timestamp': base_time, 'event_type': 'access_denied', 'username': 'agent', 'source_ip': '172.20.10.5'},
            {'timestamp': base_time + timedelta(seconds=5), 'event_type': 'access_denied', 'username': 'agent', 'source_ip': '172.20.10.5'},
            {'timestamp': base_time + timedelta(seconds=10), 'event_type': 'privilege_escalation', 'username': 'agent', 'source_ip': '172.20.10.5'},
        ]
        threats = ThreatRules.detect_suspicious_access(events, access_denied_threshold=3, time_window_minutes=10)
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'SUSPICIOUS_ACCESS'
        assert threats[0]['denial_count'] == 3

    def test_unusual_login_time_detection(self):
        # 02:00 AM login is outside standard 08:00 - 20:00
        night_time = datetime(2026, 9, 14, 2, 30, 0)
        events = [{
            'timestamp': night_time,
            'event_type': 'successful_login',
            'username': 'john.doe',
            'source_ip': '192.168.1.150'
        }]
        threats = ThreatRules.detect_unusual_login_time(events, normal_start_hour=8, normal_end_hour=20)
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'UNUSUAL_LOGIN_TIME'
        assert threats[0]['hour'] == 2


class TestThreatDetectorOrchestrator:
    """Validate ThreatDetector full workflow"""
    
    def test_orchestrator_detect_and_summarize(self):
        base_time = datetime(2026, 9, 14, 15, 0, 0)
        events = []
        # Add 6 failed logins for brute force
        for i in range(6):
            events.append({
                'timestamp': base_time + timedelta(seconds=i * 2),
                'event_type': 'failed_login',
                'username': 'root',
                'source_ip': '198.51.100.45'
            })
            
        detector = ThreatDetector()
        threats = detector.detect_all_threats(events)
        
        assert len(threats) >= 1
        summary = detector.get_threat_summary()
        assert summary['total_threats'] >= 1
        assert 'avg_risk_score' in summary
        assert summary['avg_risk_score'] > 0
