"""
Integration test suite for SentinelSOC routes and REST API endpoints.
Uses an in-memory SQLite database.
"""
import pytest
import sys
import os
from datetime import datetime, timezone

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models import db, SecurityEvent, SecurityAlert


@pytest.fixture
def app():
    """Create test application with in-memory SQLite configuration"""
    test_config = {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'test-sentinelsoc-key'
    }
    app = create_app(test_config=test_config)
    
    with app.app_context():
        db.create_all()
        
        # Populate test seed events and alert
        evt1 = SecurityEvent(
            timestamp=datetime(2026, 9, 14, 8, 30, 0),
            event_type='failed_login',
            username='admin',
            source_ip='198.51.100.45',
            risk_score=75,
            severity='HIGH',
            detected_threat='BRUTE_FORCE',
            recommendation='Block IP 198.51.100.45',
            message='Invalid password'
        )
        evt2 = SecurityEvent(
            timestamp=datetime(2026, 9, 14, 8, 35, 0),
            event_type='successful_login',
            username='alice',
            source_ip='192.168.1.100',
            risk_score=5,
            severity='LOW',
            message='Normal login'
        )
        db.session.add_all([evt1, evt2])
        db.session.commit()
        
        alert = SecurityAlert(
            event_id=evt1.id,
            threat_type='BRUTE_FORCE',
            severity='HIGH',
            risk_score=75,
            reason='6 failed login attempts from 198.51.100.45',
            recommended_action='Block source IP',
            source_ip='198.51.100.45',
            affected_users='admin',
            status='open',
            detection_timestamp=datetime.now(timezone.utc)
        )
        db.session.add(alert)
        db.session.commit()
        
        yield app
        
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


class TestDashboardRoutes:
    """Test web dashboard interface views"""
    
    def test_index_dashboard(self, client):
        response = client.get('/')
        assert response.status_code == 200
        assert b'SentinelSOC' in response.data
        assert b'Security Operations Center' in response.data
        assert b'TOTAL EVENTS' in response.data

    def test_events_page(self, client):
        response = client.get('/events')
        assert response.status_code == 200
        assert b'Security Events Explorer' in response.data
        assert b'198.51.100.45' in response.data

    def test_events_filtering(self, client):
        # Filter by severity HIGH
        res_high = client.get('/events?severity=HIGH')
        assert res_high.status_code == 200
        assert b'admin' in res_high.data
        
        # Filter by IP
        res_ip = client.get('/events?ip=192.168.1.100')
        assert res_ip.status_code == 200
        assert b'alice' in res_ip.data

    def test_event_detail_page(self, client):
        response = client.get('/event/1')
        assert response.status_code == 200
        assert b'Core Event Metadata' in response.data
        assert b'198.51.100.45' in response.data
        
        # Non-existent event returns 404
        res_404 = client.get('/event/9999')
        assert res_404.status_code == 404

    def test_alerts_page(self, client):
        response = client.get('/alerts')
        assert response.status_code == 200
        assert b'Threat Alerts & Incident Triage' in response.data
        assert b'Brute Force' in response.data or b'BRUTE FORCE' in response.data

    def test_alert_detail_page(self, client):
        response = client.get('/alert/1')
        assert response.status_code == 200
        assert b'Detection Reason & Behavioral Evidence' in response.data
        
        res_404 = client.get('/alert/9999')
        assert res_404.status_code == 404

    def test_search_page(self, client):
        # GET empty search
        res = client.get('/search')
        assert res.status_code == 200
        
        # GET with query
        res_query = client.get('/search?q=198.51.100.45')
        assert res_query.status_code == 200
        assert b'198.51.100.45' in res_query.data

    def test_report_page(self, client):
        response = client.get('/report?hours=24')
        assert response.status_code == 200
        assert b'Executive SOC Incident Report' in response.data


class TestAPIRoutes:
    """Test JSON REST API endpoints"""
    
    def test_api_health(self, client):
        res = client.get('/api/health')
        assert res.status_code == 200
        data = res.get_json()
        assert data['status'] == 'healthy'
        assert data['service'] == 'SentinelSOC'

    def test_api_stats(self, client):
        res = client.get('/api/stats')
        assert res.status_code == 200
        data = res.get_json()
        assert data['total_events'] >= 2
        assert data['total_alerts'] >= 1
        assert 'high_risk_events' in data

    def test_api_alerts(self, client):
        res = client.get('/api/alerts')
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]['threat_type'] == 'BRUTE_FORCE'

    def test_api_alert_patch_status(self, client):
        res = client.patch('/api/alerts/1', json={
            'status': 'investigating',
            'investigation_notes': 'Analyst verifying firewall drop rules'
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data['status'] == 'investigating'
        assert 'Analyst' in data['investigation_notes']

    def test_api_events(self, client):
        res = client.get('/api/events')
        assert res.status_code == 200
        data = res.get_json()
        assert 'events' in data
        assert data['total'] >= 2

    def test_api_event_detail(self, client):
        res = client.get('/api/events/1')
        assert res.status_code == 200
        data = res.get_json()
        assert 'event' in data
        assert data['event']['source_ip'] == '198.51.100.45'

    def test_api_threats(self, client):
        res = client.get('/api/threats')
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, dict)

    def test_api_top_ips(self, client):
        res = client.get('/api/top-ips')
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]['ip'] == '198.51.100.45'

    def test_api_timeline(self, client):
        res = client.get('/api/timeline?hours=24')
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, dict)

    def test_api_distributions(self, client):
        res_threat = client.get('/api/threat-distribution')
        assert res_threat.status_code == 200
        
        res_sev = client.get('/api/severity-distribution')
        assert res_sev.status_code == 200
        sev_data = res_sev.get_json()
        assert 'HIGH' in sev_data
