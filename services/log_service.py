"""
Service layer for log management, parsing, storing, and forensic filtering.
"""
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from models import db, SecurityEvent, SecurityAlert
from detector import LogParser, ThreatDetector, RiskEngine


class LogService:
    """Handle log ingestion, database persistence, threat correlation, and event querying"""
    
    @staticmethod
    def parse_and_store_logs(filepath: str, config: Dict = None) -> Dict:
        """
        Parse log file, persist events into SQLite, detect threats, and create security alerts.
        """
        parser = LogParser()
        events = parser.parse_file(filepath)
        
        if not events:
            return {
                'events_parsed': 0,
                'events_stored': 0,
                'alerts_detected': 0,
                'threats': [],
                'parsing_stats': parser.get_stats()
            }
        
        # 1. Insert security events with baseline scoring
        created_event_objects = []
        for event in events:
            base_score, severity, threat_name, rec = RiskEngine.score_single_event(event)
            sec_event = SecurityEvent(
                timestamp=event['timestamp'],
                event_type=event['event_type'],
                username=event.get('username'),
                source_ip=event.get('source_ip', '0.0.0.0'),
                destination_ip=event.get('destination_ip'),
                message=event.get('message'),
                risk_score=base_score,
                severity=severity,
                detected_threat=threat_name,
                recommendation=rec,
                status='processed'
            )
            db.session.add(sec_event)
            created_event_objects.append(sec_event)
        
        db.session.commit()
        
        # 2. Run threat detection across events
        detector = ThreatDetector(config)
        detected_threats = detector.detect_all_threats(events)
        
        # 3. Create SecurityAlert records and elevate affected SecurityEvent scores
        alert_count = 0
        for threat in detected_threats:
            source_ip = threat.get('source_ip')
            threat_type = threat.get('threat_type')
            severity = threat.get('severity')
            risk_score = threat.get('risk_score')
            reason = threat.get('reason')
            recommendation = threat.get('recommended_action')
            affected_users = ','.join(threat.get('affected_users', []))
            
            # Find matching events in database from this IP to link and elevate
            matching_events = SecurityEvent.query.filter(
                SecurityEvent.source_ip == source_ip
            ).order_by(SecurityEvent.timestamp.desc()).all()
            
            primary_event_id = matching_events[0].id if matching_events else created_event_objects[0].id
            
            # Elevate matching events within threat scope
            for evt in matching_events[:threat.get('raw_threat_data', {}).get('attempt_count', 5)]:
                if risk_score > evt.risk_score:
                    evt.risk_score = risk_score
                    evt.severity = severity
                if not evt.detected_threat:
                    evt.detected_threat = threat_type
                if not evt.recommendation:
                    evt.recommendation = recommendation
            
            # Avoid duplicate open alert for the same threat & source IP
            existing_alert = SecurityAlert.query.filter_by(
                source_ip=source_ip,
                threat_type=threat_type,
                status='open'
            ).first()
            
            if not existing_alert:
                alert = SecurityAlert(
                    event_id=primary_event_id,
                    threat_type=threat_type,
                    severity=severity,
                    risk_score=risk_score,
                    reason=reason,
                    recommended_action=recommendation,
                    status='open',
                    source_ip=source_ip,
                    affected_users=affected_users,
                    detection_timestamp=datetime.now(timezone.utc)
                )
                db.session.add(alert)
                alert_count += 1
        
        db.session.commit()
        
        return {
            'events_parsed': len(events),
            'events_stored': len(created_event_objects),
            'alerts_detected': alert_count,
            'threats': detected_threats,
            'parsing_stats': parser.get_stats()
        }
    
    @staticmethod
    def get_filtered_events(
        ip: Optional[str] = None,
        username: Optional[str] = None,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        sort_by: str = 'risk_score',
        sort_dir: str = 'desc',
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[SecurityEvent], int]:
        """
        Query security events with multi-field filtering, flexible sorting, and pagination.
        """
        query = SecurityEvent.query
        
        if ip:
            clean_ip = ip.strip()
            query = query.filter(SecurityEvent.source_ip.contains(clean_ip))
            
        if username:
            clean_user = username.strip()
            query = query.filter(SecurityEvent.username.ilike(f"%{clean_user}%"))
            
        if severity:
            clean_sev = severity.strip().upper()
            if clean_sev in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                query = query.filter(SecurityEvent.severity == clean_sev)
                
        if threat_type:
            clean_threat = threat_type.strip()
            if clean_threat != 'all':
                query = query.filter(SecurityEvent.detected_threat == clean_threat)
                
        if start_date:
            try:
                start_dt = datetime.strptime(start_date.strip(), '%Y-%m-%d')
                query = query.filter(SecurityEvent.timestamp >= start_dt)
            except ValueError:
                pass
                
        if end_date:
            try:
                end_dt = datetime.strptime(f"{end_date.strip()} 23:59:59", '%Y-%m-%d %H:%M:%S')
                query = query.filter(SecurityEvent.timestamp <= end_dt)
            except ValueError:
                pass
        
        total = query.count()
        
        # Sorting
        sort_column = getattr(SecurityEvent, sort_by, SecurityEvent.risk_score)
        if sort_dir.lower() == 'asc':
            query = query.order_by(sort_column.asc(), SecurityEvent.timestamp.desc())
        else:
            query = query.order_by(sort_column.desc(), SecurityEvent.timestamp.desc())
            
        events = query.offset(offset).limit(limit).all()
        return events, total
    
    @staticmethod
    def get_all_events(limit: int = 50, offset: int = 0) -> Tuple[List[SecurityEvent], int]:
        total = SecurityEvent.query.count()
        events = SecurityEvent.query.order_by(
            SecurityEvent.timestamp.desc()
        ).offset(offset).limit(limit).all()
        return events, total
    
    @staticmethod
    def get_events_by_ip(source_ip: str, limit: int = 100) -> List[SecurityEvent]:
        return SecurityEvent.query.filter_by(
            source_ip=source_ip.strip()
        ).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    
    @staticmethod
    def get_events_by_username(username: str, limit: int = 100) -> List[SecurityEvent]:
        return SecurityEvent.query.filter(
            SecurityEvent.username.ilike(f"%{username.strip()}%")
        ).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    
    @staticmethod
    def search_events(query: str = None, event_type: str = None, limit: int = 50) -> Tuple[List[SecurityEvent], int]:
        base_query = SecurityEvent.query
        
        if query:
            clean_q = query.strip()
            base_query = base_query.filter(
                (SecurityEvent.username.contains(clean_q)) |
                (SecurityEvent.source_ip.contains(clean_q)) |
                (SecurityEvent.message.contains(clean_q)) |
                (SecurityEvent.detected_threat.contains(clean_q))
            )
        
        if event_type:
            base_query = base_query.filter_by(event_type=event_type)
            
        total = base_query.count()
        events = base_query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
        return events, total
