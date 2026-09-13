"""
Routes package for SentinelSOC.
Exports dashboard_bp, events_bp, and api_bp.
"""
from .dashboard import dashboard_bp
from .events import events_bp
from .api import api_bp

__all__ = ['dashboard_bp', 'events_bp', 'api_bp']
