"""
SentinelSOC - Synthetic Log Generator
Generates realistic, benign, and simulated adversarial authentication/server logs.
Safe for training, testing, and SOC demonstrations.
"""
import random
import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Normal employee usernames
BENIGN_USERS = [
    'john.smith', 'alice.johnson', 'bob.wilson', 'sarah.davis',
    'mike.brown', 'emma.wilson', 'charlie.martin', 'diana.garcia',
    'frank.thomas', 'grace.lee', 'kevin.hall', 'lisa.anderson'
]

# Sensitive or targeted accounts
TARGETED_USERS = ['admin', 'root', 'administrator', 'devops_lead', 'cfo_finance', 'postgres']

# Benign internal subnets
INTERNAL_IPS = [
    '192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.105',
    '192.168.1.110', '10.0.1.15', '10.0.1.20', '10.0.2.55'
]

# Simulated adversarial / external test IPs
ADVERSARY_IPS = [
    '198.51.100.45', '203.0.113.25', '203.0.113.88',
    '192.168.50.10', '172.16.0.50', '192.168.100.1'
]


def generate_synthetic_stream(count: int = 25, scenario: str = 'all') -> str:
    """
    Generate a formatted string of synthetic log entries.
    """
    lines = []
    base_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=count * 2)
    current_time = base_time

    # Generate scenario-specific logs
    if scenario in ('all', 'brute_force'):
        attacker_ip = random.choice(ADVERSARY_IPS)
        target_user = random.choice(TARGETED_USERS)
        for _ in range(7):
            current_time += timedelta(seconds=random.randint(2, 6))
            lines.append(
                f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGIN_FAILED "
                f"username={target_user} ip={attacker_ip} message=authentication_failed"
            )

    if scenario in ('all', 'spraying'):
        sprayer_ip = random.choice(ADVERSARY_IPS)
        spray_users = random.sample(BENIGN_USERS, 5)
        for u in spray_users:
            current_time += timedelta(seconds=random.randint(5, 12))
            lines.append(
                f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGIN_FAILED "
                f"username={u} ip={sprayer_ip} message=bad_password"
            )

    if scenario in ('all', 'credential_stuffing'):
        stuff_ip = random.choice(ADVERSARY_IPS)
        victim = random.choice(['admin', 'devops_lead', 'alice.johnson'])
        for _ in range(4):
            current_time += timedelta(seconds=random.randint(3, 8))
            lines.append(
                f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGIN_FAILED "
                f"username={victim} ip={stuff_ip} message=incorrect_password"
            )
        current_time += timedelta(seconds=random.randint(2, 5))
        lines.append(
            f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGIN_SUCCESS "
            f"username={victim} ip={stuff_ip} message=login_successful_post_failures"
        )

    if scenario in ('all', 'suspicious_access'):
        violator_ip = random.choice(ADVERSARY_IPS)
        endpoints = ['/api/v1/secrets', '/admin/dump_db', '/etc/shadow', '/root/.ssh']
        for ep in endpoints:
            current_time += timedelta(seconds=random.randint(3, 7))
            lines.append(
                f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO ACCESS_DENIED "
                f"username=api_agent ip={violator_ip} message=unauthorized_access_{ep.replace('/', '_')}"
            )

    if scenario in ('all', 'off_hours'):
        # Force midnight or 03:00 AM timestamp
        off_hour_time = current_time.replace(hour=3, minute=15, second=22)
        lines.append(
            f"{off_hour_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGIN_SUCCESS "
            f"username=cfo_finance ip=192.168.1.199 message=vpn_login_established"
        )

    # Fill remaining count with benign normal traffic
    while len(lines) < count:
        current_time += timedelta(seconds=random.randint(15, 60))
        user = random.choice(BENIGN_USERS)
        ip = random.choice(INTERNAL_IPS)
        evt_type = random.choice(['LOGIN_SUCCESS', 'LOGIN_SUCCESS', 'LOGOUT', 'LOGIN_FAILED'])
        
        if evt_type == 'LOGIN_SUCCESS':
            lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGIN_SUCCESS username={user} ip={ip}")
        elif evt_type == 'LOGOUT':
            lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGOUT username={user} ip={ip}")
        else:
            lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} INFO LOGIN_FAILED username={user} ip={ip} message=password_typo")

    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description="SentinelSOC Synthetic Security Log Generator")
    parser.add_argument('-c', '--count', type=int, default=30, help="Number of log entries to generate")
    parser.add_argument(
        '-s', '--scenario',
        choices=['all', 'normal', 'brute_force', 'spraying', 'credential_stuffing', 'suspicious_access', 'off_hours'],
        default='all',
        help="Simulated scenario type"
    )
    parser.add_argument('-o', '--output', type=str, default=None, help="Output file path (default: stdout)")
    parser.add_argument('--inject-db', action='store_true', help="Directly ingest generated logs into SentinelSOC database")

    args = parser.parse_args()

    content = generate_synthetic_stream(count=args.count, scenario=args.scenario)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[+] Wrote {args.count} synthetic log entries to {out_path}")
    elif not args.inject_db:
        print(content)

    if args.inject_db:
        import tempfile
        import os
        from app import create_app
        from services import LogService
        import config

        app = create_app()
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix='.log') as tmp:
            tmp.write(content)
            tmp_name = tmp.name

        with app.app_context():
            res = LogService.parse_and_store_logs(tmp_name, config.THREAT_CONFIG)
            print(f"[+] Ingested {res['events_stored']} events into SQLite database ({res['alerts_detected']} alerts detected).")

        if os.path.exists(tmp_name):
            os.remove(tmp_name)


if __name__ == '__main__':
    main()
