"""Offline rules over normalized, trusted lab events. No commands are executed."""
import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta


def parse_time(event):
    result = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    return result


def analyze(events):
    failures, alerts = defaultdict(deque), []
    for event in sorted(events, key=parse_time):
        now, kind = parse_time(event), event['kind']
        window = failures[(event.get('src_ip'), event.get('user'))]
        while window and now - window[0] > timedelta(minutes=5):
            window.popleft()
        rule = None
        if kind == 'auth_failure':
            window.append(now)
            if len(window) == 5:
                rule = ('AUTH-001', 'medium', 'T1110', 'Five failures in five minutes')
        elif kind == 'auth_success' and len(window) >= 5:
            rule = ('AUTH-002', 'high', 'T1078', 'Success after repeated failures')
            window.clear()
        elif kind == 'process':
            name = event.get('image', '').lower().replace('\\', '/').split('/')[-1]
            tokens = event.get('command_line', '').lower().split()
            if name in ('powershell.exe', 'pwsh.exe') and any(t in ('-enc', '-encodedcommand') for t in tokens):
                rule = ('PROC-001', 'medium', 'T1059.001', 'Encoded PowerShell; inspect context')
        elif kind == 'ids_alert' and event.get('signature_id') == 1000001:
            rule = ('NET-001', 'low', None, 'Synthetic lab HTTP marker')
        if rule:
            rid, severity, technique, reason = rule
            alerts.append(dict(timestamp=event['timestamp'], rule=rid, severity=severity,
                               mitre_attack=technique, reason=reason, evidence=event))
    return alerts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events')
    args = parser.parse_args()
    with open(args.events, encoding='utf-8') as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    print(json.dumps(analyze(events), indent=2))
