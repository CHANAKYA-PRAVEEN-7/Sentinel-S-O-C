"""
Dashboard routes for SentinelSOC web interface.
Handles executive overview, incident triage, security reports, and search.
"""
from flask import Blueprint, render_template, request, abort, redirect, url_for
from models import db, SecurityEvent, SecurityAlert
from services import StatisticsService, LogService

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
def index():
    """Main SOC Dashboard view with KPI cards, charts, and recent alerts"""
    stats = StatisticsService.get_dashboard_stats()
    recent_alerts = StatisticsService.get_recent_alerts(limit=10)
    return render_template('dashboard.html', stats=stats, recent_alerts=recent_alerts)


@dashboard_bp.route('/alerts')
def alerts():
    """Alerts triage page with status/severity filtering"""
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', '').strip()
    status_filter = request.args.get('status', 'open').strip()
    limit = 25
    offset = max(0, (page - 1) * limit)
    
    query = SecurityAlert.query
    
    if status_filter and status_filter != 'all':
        query = query.filter_by(status=status_filter)
        
    if severity_filter and severity_filter != 'all':
        query = query.filter_by(severity=severity_filter)
    
    total = query.count()
    alerts_list = query.order_by(SecurityAlert.detection_timestamp.desc()).offset(offset).limit(limit).all()
    total_pages = (total + limit - 1) // limit if total > 0 else 1
    
    return render_template(
        'alerts.html',
        alerts=alerts_list,
        page=page,
        total=total,
        total_pages=total_pages,
        limit=limit,
        severity_filter=severity_filter,
        status_filter=status_filter
    )


@dashboard_bp.route('/alert/<int:alert_id>')
def alert_detail(alert_id):
    """Detailed view of a single security alert"""
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        abort(404)
    
    return render_template('alert_detail.html', alert=alert)


@dashboard_bp.route('/search', methods=['GET', 'POST'])
def search():
    """Universal search across events and alerts"""
    query = request.args.get('q', '') if request.method == 'GET' else request.form.get('query', '')
    events = []
    total = 0
    
    if query:
        events, total = LogService.search_events(query=query, limit=50)
    
    return render_template('search.html', events=events, query=query, total=total)


@dashboard_bp.route('/report')
def report():
    """SOC Executive Security Incident Report"""
    hours = request.args.get('hours', 24, type=int)
    report_data = StatisticsService.generate_report(hours=hours)
    return render_template('report.html', report=report_data, hours=hours)
