"""
SentinelSOC - Real-Time Security Operations Center
Main Flask application factory and server entrypoint.
"""
import os
import logging
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, render_template
from models import db, SecurityEvent, SecurityAlert
from routes import dashboard_bp, events_bp, api_bp
import config

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('sentinelsoc')


def create_app(test_config=None):
    """
    Application factory for SentinelSOC.
    Configures database, security headers, error handlers, and blueprints.
    """
    app = Flask(__name__)
    
    # Default configuration
    app.config['DEBUG'] = config.DEBUG
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.SQLALCHEMY_TRACK_MODIFICATIONS
    
    # Apply testing or custom configuration if passed
    if test_config:
        app.config.update(test_config)
    
    # Initialize database
    db.init_app(app)
    
    # Register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(api_bp)
    
    # Apply security HTTP headers (Section 11)
    @app.after_request
    def apply_security_headers(response):
        for header, value in config.SECURITY_HEADERS.items():
            response.headers[header] = value
        return response
    
    # Custom error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def server_error(error):
        logger.error(f"Internal server error: {error}")
        return render_template('500.html'), 500
    
    # Ensure database schema is created
    with app.app_context():
        db.create_all()
        logger.debug("Database tables verified/created.")
    
    return app


def seed_initial_logs_if_empty(app):
    """Populate database with sample logs on first launch if empty"""
    with app.app_context():
        if SecurityEvent.query.count() == 0:
            logger.info("Database is empty. Ingesting sample security logs...")
            from services import LogService
            
            # Look for auth.log and suspicious_activity.log
            sample_files = [
                Path(config.SAMPLE_LOGS_DIR) / 'auth.log',
                Path(config.SAMPLE_LOGS_DIR) / 'suspicious_activity.log'
            ]
            
            for log_file in sample_files:
                if log_file.exists():
                    try:
                        res = LogService.parse_and_store_logs(str(log_file), config.THREAT_CONFIG)
                        logger.info(
                            f"Loaded {log_file.name}: {res['events_stored']} events, "
                            f"{res['alerts_detected']} alerts created."
                        )
                    except Exception as e:
                        logger.error(f"Failed loading {log_file.name}: {e}")


if __name__ == '__main__':
    app = create_app()
    seed_initial_logs_if_empty(app)
    
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5000))
    
    logger.info(f"🛡️  SentinelSOC is live at http://{host}:{port}")
    app.run(debug=config.DEBUG, host=host, port=port)
