"""
Log parser for SentinelSOC - parses authentication and server security logs.
"""
from datetime import datetime
import re
from typing import Dict, List, Optional


class LogParser:
    """Parse authentication and security log lines into structured event dictionaries"""
    
    # Matches: YYYY-MM-DD HH:MM:SS LEVEL EVENT_TYPE [key=value pairs or trailing message]
    LOG_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'(?P<level>[A-Z]+)\s+'
        r'(?P<event_type>[A-Za-z0-9_]+)'
        r'(?P<details>.*)$'
    )
    
    # Matches key=value, key="value with spaces", or key='value'
    KEY_VALUE_PATTERN = re.compile(
        r'(?P<key>[a-zA-Z_]+)=(?:"(?P<qval>[^"]*)"|\'(?P<sqval>[^\']*)\'|(?P<rawval>[^\s]+))'
    )
    
    # Standard mapping for common event types
    KNOWN_EVENTS = {
        'LOGIN_SUCCESS': 'successful_login',
        'LOGIN_FAILED': 'failed_login',
        'LOGOUT': 'logout',
        'INVALID_USER': 'invalid_user',
        'INVALID_PASSWORD': 'invalid_password',
        'ACCOUNT_LOCKED': 'account_locked',
        'PRIVILEGE_ESCALATION': 'privilege_escalation',
        'ACCESS_DENIED': 'access_denied',
        'SUSPICIOUS_REQUEST': 'suspicious_request',
        'SUDO_ATTEMPT': 'sudo_attempt',
        'SSH_CONNECTION': 'ssh_connection',
        'UNUSUAL_LOGIN_TIME': 'unusual_login_time'
    }
    
    def __init__(self):
        self.parsed_events: List[Dict] = []
        self.parsing_errors: List[str] = []
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single log line into structured event dictionary.
        
        Args:
            line: Raw log line string
            
        Returns:
            Dictionary with parsed event data or None if parsing failed
        """
        try:
            line = line.strip()
            if not line or line.startswith('#'):
                return None
            
            match = self.LOG_PATTERN.match(line)
            if not match:
                self.parsing_errors.append(f"Could not match pattern: {line}")
                return None
            
            groups = match.groupdict()
            timestamp_str = groups.get('timestamp')
            event_type_raw = groups.get('event_type')
            details_str = groups.get('details', '').strip()
            
            # Parse timestamp
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                self.parsing_errors.append(f"Invalid timestamp format: {timestamp_str}")
                return None
            
            # Normalize event type
            event_type = self.KNOWN_EVENTS.get(event_type_raw.upper(), event_type_raw.lower())
            
            # Extract key-value pairs
            details = self._parse_details(details_str)
            
            # Extract username from various possible keys
            username = details.get('username') or details.get('user') or details.get('account')
            
            # Extract IP from various possible keys
            source_ip = (
                details.get('ip') or
                details.get('source_ip') or
                details.get('src_ip') or
                details.get('client_ip') or
                '0.0.0.0'
            )
            
            # Extract destination IP
            destination_ip = (
                details.get('dest_ip') or
                details.get('destination_ip') or
                details.get('dst_ip')
            )
            
            # Extract message or build fallback
            message = details.get('message') or details.get('msg')
            if not message and details_str:
                # Remove known parsed pairs to get leftover message if any
                clean_msg = self.KEY_VALUE_PATTERN.sub('', details_str).strip()
                message = clean_msg if clean_msg else f"{event_type_raw} event for {username or 'unknown'}"
            elif not message:
                message = f"{event_type_raw} event"
            
            # Replace underscores with spaces in messages for readability if unquoted
            if '_' in message and ' ' not in message:
                message = message.replace('_', ' ')
            
            event = {
                'timestamp': timestamp,
                'event_type': event_type,
                'level': groups.get('level', 'INFO'),
                'username': username,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'message': message,
                'raw_line': line,
                'raw_details': details
            }
            
            return event
            
        except Exception as e:
            self.parsing_errors.append(f"Exception parsing line '{line}': {str(e)}")
            return None
    
    def _parse_details(self, details_str: str) -> Dict:
        """Parse key=value pairs handling quotes and escaped characters"""
        details = {}
        for match in self.KEY_VALUE_PATTERN.finditer(details_str):
            key = match.group('key').lower()
            val = match.group('qval') or match.group('sqval') or match.group('rawval')
            details[key] = val
        return details
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """Parse an entire log file"""
        self.parsed_events = []
        self.parsing_errors = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    event = self.parse_line(line)
                    if event:
                        self.parsed_events.append(event)
            return self.parsed_events
        except FileNotFoundError:
            self.parsing_errors.append(f"File not found: {filepath}")
            return []
        except Exception as e:
            self.parsing_errors.append(f"Error reading file {filepath}: {str(e)}")
            return []
    
    def parse_string(self, content: str) -> List[Dict]:
        """Parse log content from raw string"""
        self.parsed_events = []
        self.parsing_errors = []
        
        for line in content.splitlines():
            event = self.parse_line(line)
            if event:
                self.parsed_events.append(event)
        return self.parsed_events
    
    def get_stats(self) -> Dict:
        """Return parsing statistics"""
        return {
            'total_lines_parsed': len(self.parsed_events),
            'total_errors': len(self.parsing_errors),
            'event_types': self._count_by_field('event_type'),
            'errors': self.parsing_errors[:10]
        }
    
    def _count_by_field(self, field: str) -> Dict:
        counts = {}
        for event in self.parsed_events:
            val = event.get(field, 'unknown')
            counts[val] = counts.get(val, 0) + 1
        return counts
