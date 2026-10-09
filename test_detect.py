import unittest
from detect import analyze


def event(time, kind='auth_failure', user='a'):
    return dict(timestamp='2026-01-01T' + time + 'Z', kind=kind, user=user, src_ip='192.0.2.1')


class DetectionTests(unittest.TestCase):
    def test_threshold_and_success(self):
        data = [event('12:00:00') for _ in range(5)] + [event('12:01:00', 'auth_success')]
        self.assertEqual([a['rule'] for a in analyze(data)], ['AUTH-001', 'AUTH-002'])

    def test_outside_window(self):
        self.assertEqual(analyze([event('12:00:00') for _ in range(4)] + [event('12:06:00')]), [])

    def test_user_isolation(self):
        self.assertEqual(analyze([event('12:00:00', user=str(i)) for i in range(5)]), [])

    def test_process(self):
        e = event('12:00:00', 'process')
        e.update(image='powershell.exe', command_line='powershell.exe Get-Date')
        self.assertEqual(analyze([e]), [])
        e['command_line'] = 'powershell.exe -enc fixture'
        self.assertEqual(analyze([e])[0]['rule'], 'PROC-001')

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            analyze([dict(timestamp='2026-01-01T00:00:00', kind='process')])

    def test_fixture(self):
        import json
        from pathlib import Path
        data = [json.loads(x) for x in Path(__file__).with_name('events.jsonl').read_text().splitlines()]
        self.assertEqual([a['rule'] for a in analyze(data)], ['AUTH-001', 'AUTH-002', 'PROC-001', 'NET-001'])


if __name__ == '__main__':
    unittest.main()
