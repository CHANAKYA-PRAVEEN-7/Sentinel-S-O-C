"""
REST API routes for SentinelSOC.
Provides structured JSON endpoints for real-time polling, dashboards, and integrations.
"""
from flask import Blueprint, jsonify, request
from datetime import datetime, timezone
from models import db, SecurityEvent, SecurityAlert, DailyMetrics
from services import StatisticsService, LogService
import tempfile
import os

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get top-level dashboard KPI statistics"""
    stats = StatisticsService.get_dashboard_stats()
    return jsonify(stats)


@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Get active or filtered alerts"""
    limit = request.args.get('limit', 20, type=int)
    severity = request.args.get('severity')
    status = request.args.get('status', 'open')
    
    query = SecurityAlert.query
    if status and status != 'all':
        query = query.filter_by(status=status)
    if severity and severity != 'all':
        query = query.filter_by(severity=severity)
        
    alerts = query.order_by(SecurityAlert.detection_timestamp.desc()).limit(limit).all()
    return jsonify([alert.to_dict() for alert in alerts])


@api_bp.route('/alerts/<int:alert_id>', methods=['GET', 'PATCH'])
def alert_detail(alert_id):
    """Retrieve or update an individual alert status"""
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
        
    if request.method == 'GET':
        return jsonify(alert.to_dict())
        
    # Handle PATCH update (e.g. status transition or notes)
    data = request.get_json(silent=True) or {}
    
    if 'status' in data:
        new_status = data['status'].lower()
        if new_status in ('open', 'investigating', 'resolved'):
            alert.status = new_status
            if new_status == 'resolved' and not alert.resolved_at:
                alert.resolved_at = datetime.now(timezone.utc)
            elif new_status != 'resolved':
                alert.resolved_at = None
                
    if 'investigation_notes' in data:
        alert.investigation_notes = data['investigation_notes']
        
    db.session.commit()
    return jsonify(alert.to_dict())


@api_bp.route('/events', methods=['GET'])
def get_events():
    """Get filtered and paginated security events"""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    ip = request.args.get('ip') or request.args.get('source_ip')
    username = request.args.get('username')
    severity = request.args.get('severity')
    threat_type = request.args.get('threat_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    sort_by = request.args.get('sort_by', 'timestamp')
    sort_dir = request.args.get('sort_dir', 'desc')
    
    events, total = LogService.get_filtered_events(
        ip=ip,
        username=username,
        severity=severity,
        threat_type=threat_type,
        start_date=start_date,
        end_date=end_date,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=limit,
        offset=offset
    )
    
    return jsonify({
        'total': total,
        'limit': limit,
        'offset': offset,
        'events': [e.to_dict() for e in events]
    })


@api_bp.route('/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    """Get complete forensic details for a single event"""
    details = StatisticsService.get_event_details(event_id)
    if not details:
        return jsonify({'error': 'Event not found'}), 404
    return jsonify(details)


@api_bp.route('/threats', methods=['GET'])
def get_threats():
    """Get aggregate threat count breakdown"""
    distribution = StatisticsService.get_threat_distribution()
    return jsonify(distribution)


@api_bp.route('/top-ips', methods=['GET'])
def get_top_ips():
    """Get top suspicious IPs ranked by threat impact"""
    limit = request.args.get('limit', 10, type=int)
    ips = StatisticsService.get_top_suspicious_ips(limit)
    return jsonify(ips)


@api_bp.route('/threat-distribution', methods=['GET'])
def get_threat_distribution():
    """Get threat type distribution for doughnut charts"""
    distribution = StatisticsService.get_threat_distribution()
    return jsonify(distribution)


@api_bp.route('/severity-distribution', methods=['GET'])
def get_severity_distribution():
    """Get severity category distribution for bar charts"""
    distribution = StatisticsService.get_severity_distribution()
    return jsonify(distribution)


@api_bp.route('/timeline', methods=['GET'])
def get_timeline():
    """Get hourly event timeline for line charts"""
    hours = request.args.get('hours', 24, type=int)
    timeline = StatisticsService.get_events_timeline(hours)
    return jsonify(timeline)


@api_bp.route('/health', methods=['GET'])
def health():
    """System health and heartbeat check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'service': 'SentinelSOC',
        'version': '1.0.0'
    })


@api_bp.route('/import-logs', methods=['POST'])
def import_logs():
    """Upload and ingest custom log file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400
        
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix='.log') as tmp:
            content = file.stream.read().decode('utf-8', errors='replace')
            tmp.write(content)
            tmp_path = tmp.name
            
        import config
        result = LogService.parse_and_store_logs(tmp_path, config.THREAT_CONFIG)
        
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
            
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/generate-logs', methods=['POST'])
def trigger_generate_logs():
    """Trigger on-demand synthetic log generation for live demos"""
    try:
        from generate_logs import generate_synthetic_stream
        import config
        
        count = request.json.get('count', 15) if request.is_json else 15
        stream = generate_synthetic_stream(count=count)
        
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix='.log') as tmp:
            tmp.write(stream)
            tmp_path = tmp.name
            
        result = LogService.parse_and_store_logs(tmp_path, config.THREAT_CONFIG)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
            
        return jsonify({
            'status': 'success',
            'message': f"Generated and analyzed {count} synthetic security events",
            'result': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
