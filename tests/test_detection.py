
import pandas as pd
from src.detectors.brute_force import detect_brute_force
from src.detectors.password_spray import detect_password_spray


def create_test_logs():
    return pd.DataFrame([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "192.0.2.10",
            "status": "Success"
        },
        {
            "createdDateTime": "2026-11-07T09:02:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:02:30Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:03:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:03:30Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:04:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:05:00Z",
            "userPrincipalName": "charlie@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:05:30Z",
            "userPrincipalName": "david@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:06:00Z",
            "userPrincipalName": "emma@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        }
    ])


def test_brute_force_detected():
    logs = create_test_logs()

    alerts = detect_brute_force(logs)

    assert len(alerts) == 1
    assert alerts[0]["user"] == "bob@demo.local"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["severity"] == "High"


def test_no_brute_force():
    logs = pd.DataFrame([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "192.0.2.10",
            "status": "Failure"
        }
    ])

    alerts = detect_brute_force(logs)

    assert len(alerts) == 0


def test_password_spray_detected():
    logs = create_test_logs()

    alerts = detect_password_spray(logs)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "198.51.100.20"
    assert alerts[0]["distinct_users"] == 3
    assert alerts[0]["severity"] == "High"


def test_no_password_spray():
    logs = pd.DataFrame([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "192.0.2.10",
            "status": "Failure"
        }
    ])

    alerts = detect_password_spray(logs)

    assert len(alerts) == 0

def test_brute_force_outside_time_window():
    logs = pd.DataFrame([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:20:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        }
    ])

    alerts = detect_brute_force(
        logs,
        threshold=2,
        window_minutes=10
    )

    assert len(alerts) == 0


def test_same_user_does_not_trigger_password_spray():
    logs = pd.DataFrame([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:01:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:02:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        }
    ])

    alerts = detect_password_spray(
        logs,
        threshold=3,
        window_minutes=10
    )

    assert len(alerts) == 0
