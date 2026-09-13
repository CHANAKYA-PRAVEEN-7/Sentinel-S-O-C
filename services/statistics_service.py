"""
Service layer for SOC statistics, aggregated metrics, and timeline reporting.
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
from models import db, SecurityEvent, SecurityAlert, DailyMetrics
from sqlalchemy import func


class StatisticsService:
    """Generate executive dashboard KPIs, incident distributions, and threat metrics"""
    
    @staticmethod
    def get_dashboard_stats() -> Dict[str, Any]:
        """Get top SOC KPIs matching requirements: Total Events, Active Alerts, Critical Threats, High Risk Events"""
        total_events = SecurityEvent.query.count()
        active_alerts = SecurityAlert.query.filter_by(status='open').count()
        critical_threats = SecurityAlert.query.filter_by(status='open', severity='CRITICAL').count()
        high_threats = SecurityAlert.query.filter_by(status='open', severity='HIGH').count()
        medium_threats = SecurityAlert.query.filter_by(status='open', severity='MEDIUM').count()
        low_threats = SecurityAlert.query.filter_by(status='open', severity='LOW').count()
        
        # High Risk Events = count of events with risk_score >= 60 (High or Critical)
        high_risk_events = SecurityEvent.query.filter(SecurityEvent.risk_score >= 60).count()
        
        # Average risk score across active alerts
        avg_risk = db.session.query(func.avg(SecurityAlert.risk_score)).filter_by(status='open').scalar() or 0
        
        # 24-hour delta metrics
        yesterday = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
        events_24h = SecurityEvent.query.filter(SecurityEvent.timestamp >= yesterday).count()
        alerts_24h = SecurityAlert.query.filter(SecurityAlert.detection_timestamp >= yesterday).count()
        
        unique_ips = db.session.query(func.count(func.distinct(SecurityEvent.source_ip))).scalar() or 0
        unique_users = db.session.query(func.count(func.distinct(SecurityEvent.username))).filter(
            SecurityEvent.username.isnot(None)
        ).scalar() or 0
        
        return {
            'total_events': total_events,
            'total_alerts': active_alerts,
            'critical_threats': critical_threats,
            'high_threats': high_threats,
            'high_risk_events': high_risk_events,
            'medium_threats': medium_threats,
            'low_threats': low_threats,
            'avg_risk_score': round(float(avg_risk), 1),
            'events_24h': events_24h,
            'alerts_24h': alerts_24h,
            'unique_ips': unique_ips,
            'unique_users': unique_users
        }
    
    @staticmethod
    def get_recent_alerts(limit: int = 15) -> List[Dict]:
        """Get recent alerts with associated metadata"""
        alerts = SecurityAlert.query.order_by(
            SecurityAlert.detection_timestamp.desc()
        ).limit(limit).all()
        return [alert.to_dict() for alert in alerts]
    
    @staticmethod
    def get_events_timeline(hours: int = 24) -> Dict[str, int]:
        """
        Get events frequency grouped by hour for Chart.js timeline.
        """
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
        events = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= cutoff
        ).order_by(SecurityEvent.timestamp.asc()).all()
        
        # If no events found in the window, fallback to all recent events for demo visualization
        if not events:
            events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(100).all()
            events.reverse()
        
        timeline: Dict[str, int] = {}
        for evt in events:
            hour_str = evt.timestamp.strftime('%H:00')
            timeline[hour_str] = timeline.get(hour_str, 0) + 1
        
        return timeline
    
    @staticmethod
    def get_threat_distribution() -> Dict[str, int]:
        """Get distribution of active threat types"""
        threats = db.session.query(
            SecurityAlert.threat_type,
            func.count(SecurityAlert.id)
        ).filter_by(status='open').group_by(SecurityAlert.threat_type).all()
        
        distribution = {threat_type.replace('_', ' ').title(): count for threat_type, count in threats}
        
        # If no open alerts, provide baseline keys so charts display smoothly
        if not distribution:
            distribution = {'Normal Baseline': 1}
            
        return distribution
    
    @staticmethod
    def get_severity_distribution() -> Dict[str, int]:
        """Get counts across CRITICAL, HIGH, MEDIUM, LOW severities"""
        severities = db.session.query(
            SecurityAlert.severity,
            func.count(SecurityAlert.id)
        ).filter_by(status='open').group_by(SecurityAlert.severity).all()
        
        sev_map = {sev: count for sev, count in severities}
        return {
            'CRITICAL': sev_map.get('CRITICAL', 0),
            'HIGH': sev_map.get('HIGH', 0),
            'MEDIUM': sev_map.get('MEDIUM', 0),
            'LOW': sev_map.get('LOW', 0),
        }
    
    @staticmethod
    def get_top_suspicious_ips(limit: int = 5) -> List[Dict]:
        """Get top suspicious IPs ranked by threat count and maximum risk score"""
        results = db.session.query(
            SecurityAlert.source_ip,
            func.count(SecurityAlert.id).label('alert_count'),
            func.max(SecurityAlert.risk_score).label('max_risk_score')
        ).filter_by(status='open').group_by(SecurityAlert.source_ip).order_by(
            func.max(SecurityAlert.risk_score).desc(),
            func.count(SecurityAlert.id).desc()
        ).limit(limit).all()
        
        return [
            {
                'ip': r.source_ip,
                'alert_count': r.alert_count,
                'max_risk_score': r.max_risk_score or 0
            }
            for r in results
        ]
    
    @staticmethod
    def get_event_details(event_id: int) -> Dict[str, Any]:
        """Get comprehensive forensic details for a single event"""
        event = db.session.get(SecurityEvent, event_id)
        if not event:
            return None
        
        related_alerts = SecurityAlert.query.filter_by(event_id=event_id).all()
        
        # Correlated events from the same source IP (excluding current event)
        correlated_events = SecurityEvent.query.filter(
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.id != event.id
        ).order_by(SecurityEvent.timestamp.desc()).limit(8).all()
        
        return {
            'event': event.to_dict(),
            'related_alerts': [a.to_dict() for a in related_alerts],
            'correlated_events': [e.to_dict() for e in correlated_events]
        }
    
    @staticmethod
    def generate_report(hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive SOC incident summary report"""
        stats = StatisticsService.get_dashboard_stats()
        return {
            'report_time': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'period_hours': hours,
            'summary': stats,
            'threat_distribution': StatisticsService.get_threat_distribution(),
            'severity_distribution': StatisticsService.get_severity_distribution(),
            'top_ips': StatisticsService.get_top_suspicious_ips(10),
            'timeline': StatisticsService.get_events_timeline(hours),
            'recent_alerts': StatisticsService.get_recent_alerts(15)
        }
