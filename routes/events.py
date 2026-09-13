"""
Events Blueprint for SentinelSOC.
Handles the Events Exploration page, advanced forensic filtering, search, and event details.
"""
from flask import Blueprint, render_template, request, abort
from models import db, SecurityEvent, SecurityAlert
from services import LogService, StatisticsService

events_bp = Blueprint('events', __name__)


@events_bp.route('/events')
def events():
    """
    Event management page.
    Supports filtering by IP, username, severity, threat type, date range,
    and sorting by risk score or timestamp.
    """
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 25, type=int)
    offset = max(0, (page - 1) * limit)
    
    # Filter parameters
    ip = request.args.get('ip', '').strip()
    username = request.args.get('username', '').strip()
    severity = request.args.get('severity', '').strip()
    threat_type = request.args.get('threat_type', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    
    # Sorting parameters
    sort_by = request.args.get('sort_by', 'risk_score')
    sort_dir = request.args.get('sort_dir', 'desc')
    
    events_list, total = LogService.get_filtered_events(
        ip=ip or None,
        username=username or None,
        severity=severity or None,
        threat_type=threat_type or None,
        start_date=start_date or None,
        end_date=end_date or None,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=limit,
        offset=offset
    )
    
    # Get distinct threat types for the dropdown filter
    all_threat_types = [
        'BRUTE_FORCE',
        'PASSWORD_SPRAYING',
        'SUCCESSFUL_LOGIN_AFTER_FAILURES',
        'ACCOUNT_ENUMERATION',
        'SUSPICIOUS_ACCESS',
        'UNUSUAL_LOGIN_TIME',
        'PRIVILEGE_ESCALATION_ATTEMPT',
        'ACCOUNT_LOCKOUT',
        'SUSPICIOUS_REQUEST'
    ]
    
    total_pages = (total + limit - 1) // limit if total > 0 else 1
    
    return render_template(
        'events.html',
        events=events_list,
        total=total,
        page=page,
        total_pages=total_pages,
        limit=limit,
        ip=ip,
        username=username,
        severity=severity,
        threat_type=threat_type,
        start_date=start_date,
        end_date=end_date,
        sort_by=sort_by,
        sort_dir=sort_dir,
        threat_types=all_threat_types
    )


@events_bp.route('/event/<int:event_id>')
def event_detail(event_id):
    """
    Forensic event inspection page.
    Displays detailed event telemetry, detection reasons, risk score breakdown,
    remediation playbook, and correlated IP events.
    """
    event = db.session.get(SecurityEvent, event_id)
    if not event:
        abort(404)
        
    details = StatisticsService.get_event_details(event_id)
    return render_template('event_detail.html', details=details, event=event)
