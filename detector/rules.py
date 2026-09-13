"""
Threat detection rules for SentinelSOC.
Implements detection logic for Brute Force, Password Spraying, Login After Failures,
Account Enumeration, Suspicious Access, and Unusual Login Times.
"""
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict


class ThreatRules:
    """Evaluate security event streams against behavioral and heuristic threat patterns"""
    
    @staticmethod
    def detect_brute_force(
        events: List[Dict],
        threshold: int = 5,
        time_window_minutes: int = 5
    ) -> List[Dict]:
        """
        Rule A: Brute Force Detection
        Detects multiple failed login attempts targeting an account from the same IP within a time window.
        """
        threats = []
        ip_attempts = defaultdict(list)
        
        # Group failed attempts by IP
        for event in events:
            if event['event_type'] in ['failed_login', 'invalid_password', 'account_locked']:
                ip = event.get('source_ip')
                if ip:
                    ip_attempts[ip].append(event)
        
        for ip, attempt_events in ip_attempts.items():
            if len(attempt_events) >= threshold:
                sorted_events = sorted(attempt_events, key=lambda x: x['timestamp'])
                first_time = sorted_events[0]['timestamp']
                last_time = sorted_events[-1]['timestamp']
                time_diff = max(0.1, (last_time - first_time).total_seconds() / 60.0)
                
                if time_diff <= time_window_minutes:
                    usernames = sorted(list(set(e.get('username') for e in sorted_events if e.get('username'))))
                    severity = 'CRITICAL' if len(sorted_events) >= 10 else 'HIGH'
                    
                    threats.append({
                        'threat_type': 'BRUTE_FORCE',
                        'source_ip': ip,
                        'affected_users': usernames or ['unknown'],
                        'attempt_count': len(sorted_events),
                        'time_window_minutes': round(time_diff, 2),
                        'first_attempt': first_time,
                        'last_attempt': last_time,
                        'suggested_severity': severity,
                        'events': sorted_events
                    })
        
        return threats
    
    @staticmethod
    def detect_password_spraying(
        events: List[Dict],
        unique_user_threshold: int = 3,
        time_window_minutes: int = 10
    ) -> List[Dict]:
        """
        Rule B: Password Spraying Detection
        Detects horizontal authentication failures where an attacker attempts passwords against
        multiple distinct user accounts from a single source IP.
        """
        threats = []
        ip_attempts = defaultdict(list)
        
        for event in events:
            if event['event_type'] in ['failed_login', 'invalid_user', 'invalid_password']:
                ip = event.get('source_ip')
                if ip:
                    ip_attempts[ip].append(event)
        
        for ip, attempt_events in ip_attempts.items():
            users_targeted = set(e.get('username') for e in attempt_events if e.get('username'))
            
            if len(users_targeted) >= unique_user_threshold:
                sorted_events = sorted(attempt_events, key=lambda x: x['timestamp'])
                first_time = sorted_events[0]['timestamp']
                last_time = sorted_events[-1]['timestamp']
                time_diff = max(0.1, (last_time - first_time).total_seconds() / 60.0)
                
                if time_diff <= time_window_minutes:
                    severity = 'HIGH' if len(users_targeted) >= 5 else 'MEDIUM'
                    threats.append({
                        'threat_type': 'PASSWORD_SPRAYING',
                        'source_ip': ip,
                        'affected_users': sorted(list(users_targeted)),
                        'unique_user_count': len(users_targeted),
                        'attempt_count': len(attempt_events),
                        'time_window_minutes': round(time_diff, 2),
                        'first_attempt': first_time,
                        'last_attempt': last_time,
                        'suggested_severity': severity,
                        'events': sorted_events
                    })
        
        return threats
    
    @staticmethod
    def detect_successful_login_after_failures(
        events: List[Dict],
        failure_threshold: int = 3,
        time_window_minutes: int = 5
    ) -> List[Dict]:
        """
        Rule C: Successful Login After Multiple Failures
        Detects when a successful login occurs shortly after multiple failed authentication attempts
        from the same source IP, indicating probable credential cracking or account takeover.
        """
        threats = []
        ip_user_events = defaultdict(lambda: defaultdict(list))
        
        for event in events:
            ip = event.get('source_ip')
            username = event.get('username')
            if ip and username:
                ip_user_events[ip][username].append(event)
        
        for ip, user_dict in ip_user_events.items():
            for username, events_list in user_dict.items():
                sorted_events = sorted(events_list, key=lambda x: x['timestamp'])
                successful = [e for e in sorted_events if e['event_type'] == 'successful_login']
                failures = [e for e in sorted_events if e['event_type'] in ['failed_login', 'invalid_password']]
                
                if successful and failures:
                    for success_evt in successful:
                        success_time = success_evt['timestamp']
                        prior_failures = [
                            f for f in failures 
                            if 0 < (success_time - f['timestamp']).total_seconds() <= (time_window_minutes * 60)
                        ]
                        
                        if len(prior_failures) >= failure_threshold:
                            severity = 'CRITICAL' if len(prior_failures) >= 6 else 'HIGH'
                            threats.append({
                                'threat_type': 'SUCCESSFUL_LOGIN_AFTER_FAILURES',
                                'source_ip': ip,
                                'username': username,
                                'affected_users': [username],
                                'failed_attempts': len(prior_failures),
                                'successful_login_time': success_time,
                                'time_window_minutes': time_window_minutes,
                                'suggested_severity': severity,
                                'events': prior_failures + [success_evt]
                            })
                            break
        
        return threats
    
    @staticmethod
    def detect_account_enumeration(
        events: List[Dict],
        unique_user_threshold: int = 4,
        time_window_minutes: int = 15
    ) -> List[Dict]:
        """
        Rule D: Account Enumeration Detection
        Detects repeated attempts probing for valid accounts by generating 'invalid_user' events.
        """
        threats = []
        ip_attempts = defaultdict(list)
        
        for event in events:
            if event['event_type'] in ['invalid_user', 'failed_login']:
                ip = event.get('source_ip')
                if ip:
                    ip_attempts[ip].append(event)
        
        for ip, attempt_events in ip_attempts.items():
            users_probed = set(e.get('username') for e in attempt_events if e.get('username'))
            
            if len(users_probed) >= unique_user_threshold:
                sorted_events = sorted(attempt_events, key=lambda x: x['timestamp'])
                first_time = sorted_events[0]['timestamp']
                last_time = sorted_events[-1]['timestamp']
                time_diff = max(0.1, (last_time - first_time).total_seconds() / 60.0)
                
                if time_diff <= time_window_minutes:
                    threats.append({
                        'threat_type': 'ACCOUNT_ENUMERATION',
                        'source_ip': ip,
                        'affected_users': sorted(list(users_probed)),
                        'unique_user_count': len(users_probed),
                        'attempt_count': len(attempt_events),
                        'time_window_minutes': round(time_diff, 2),
                        'suggested_severity': 'MEDIUM',
                        'events': sorted_events
                    })
        
        return threats
    
    @staticmethod
    def detect_suspicious_access(
        events: List[Dict],
        access_denied_threshold: int = 3,
        time_window_minutes: int = 10
    ) -> List[Dict]:
        """
        Rule E: Suspicious Access Detection
        Detects repeated access denied, privilege escalation, or suspicious request attempts.
        """
        threats = []
        ip_events = defaultdict(list)
        
        suspicious_types = ['access_denied', 'privilege_escalation', 'suspicious_request', 'sudo_attempt']
        
        for event in events:
            if event['event_type'] in suspicious_types:
                ip = event.get('source_ip')
                if ip:
                    ip_events[ip].append(event)
        
        for ip, denial_events in ip_events.items():
            if len(denial_events) >= access_denied_threshold:
                sorted_events = sorted(denial_events, key=lambda x: x['timestamp'])
                first_time = sorted_events[0]['timestamp']
                last_time = sorted_events[-1]['timestamp']
                time_diff = max(0.1, (last_time - first_time).total_seconds() / 60.0)
                
                if time_diff <= time_window_minutes:
                    usernames = sorted(list(set(e.get('username') for e in sorted_events if e.get('username'))))
                    severity = 'HIGH' if len(denial_events) >= 6 else 'MEDIUM'
                    
                    threats.append({
                        'threat_type': 'SUSPICIOUS_ACCESS',
                        'source_ip': ip,
                        'affected_users': usernames or ['system/root'],
                        'denial_count': len(denial_events),
                        'time_window_minutes': round(time_diff, 2),
                        'suggested_severity': severity,
                        'events': sorted_events
                    })
        
        return threats
    
    @staticmethod
    def detect_unusual_login_time(
        events: List[Dict],
        normal_start_hour: int = 8,
        normal_end_hour: int = 20
    ) -> List[Dict]:
        """
        Rule F: Unusual Login Time Detection
        Detects successful authentications occurring outside standard business hours.
        """
        threats = []
        
        for event in events:
            if event['event_type'] == 'successful_login':
                timestamp = event['timestamp']
                hour = timestamp.hour
                
                if hour < normal_start_hour or hour >= normal_end_hour:
                    # Severity: earlier in the morning (midnight-6am) is MEDIUM, late evening is LOW
                    severity = 'MEDIUM' if (0 <= hour < 5 or hour >= 23) else 'LOW'
                    threats.append({
                        'threat_type': 'UNUSUAL_LOGIN_TIME',
                        'username': event.get('username') or 'unknown',
                        'affected_users': [event.get('username')] if event.get('username') else [],
                        'source_ip': event.get('source_ip'),
                        'login_time': timestamp,
                        'hour': hour,
                        'normal_hours': f"{normal_start_hour:02d}:00 - {normal_end_hour:02d}:00",
                        'suggested_severity': severity,
                        'events': [event]
                    })
        
        return threats
