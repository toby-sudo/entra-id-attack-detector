
import json
import pandas as pd
import pytest

from src.detectors.brute_force import detect_brute_force
from src.detectors.password_spray import detect_password_spray
from src.detectors.failure_then_success import detect_failure_then_success

from src.reports.report_generator import (
    generate_alert_report,
    generate_alert_id
)

from src.reports.investigation_manager import update_alert_status


def make_logs(events):
    return pd.DataFrame(events)


def make_sample_alerts():
    return [
        {
            "alert_name": "Brute Force Login Attempt",
            "user": "bob@demo.local",
            "source_ip": "192.0.2.11",
            "failed_attempts": 5,
            "severity": "High",
            "mitre_technique": "T1110 - Brute Force"
        },
        {
            "alert_name": "Possible Password Spray",
            "source_ip": "198.51.100.20",
            "affected_users": [
                "charlie@demo.local",
                "david@demo.local",
                "emma@demo.local"
            ],
            "distinct_users": 3,
            "severity": "High",
            "mitre_technique": "T1110.003 - Password Spraying"
        },
        {
            "alert_name": "Successful Login After Repeated Failures",
            "user": "bob@demo.local",
            "source_ip": "192.0.2.11",
            "failed_attempts": 5,
            "severity": "High",
            "mitre_technique": "T1110 - Brute Force"
        }
    ]


# BRUTE-FORCE DETECTION TESTS

def test_brute_force_detected():
    events = []

    for minute in range(5):
        events.append({
            "createdDateTime": f"2026-11-07T09:0{minute}:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        })

    alerts = detect_brute_force(make_logs(events))

    assert len(alerts) == 1
    assert alerts[0]["alert_name"] == "Brute Force Login Attempt"
    assert alerts[0]["failed_attempts"] == 5


def test_no_brute_force():
    logs = make_logs([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "192.0.2.10",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:01:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "192.0.2.10",
            "status": "Failure"
        }
    ])

    assert detect_brute_force(logs) == []


def test_brute_force_outside_time_window():
    logs = make_logs([
        {
            "createdDateTime": f"2026-11-07T09:{minute:02d}:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        }
        for minute in [0, 15, 30, 45, 50]
    ])

    assert detect_brute_force(logs) == []


def test_brute_force_missing_required_columns():
    logs = make_logs([
        {
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        }
    ])

    with pytest.raises(ValueError, match="Missing column"):
        detect_brute_force(logs)


# PASSWORD-SPRAY DETECTION TESTS

def test_password_spray_detected():
    logs = make_logs([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
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
            "userPrincipalName": "charlie@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        }
    ])

    alerts = detect_password_spray(logs)

    assert len(alerts) == 1
    assert alerts[0]["alert_name"] == "Possible Password Spray"
    assert alerts[0]["distinct_users"] == 3


def test_no_password_spray():
    logs = make_logs([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:01:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        }
    ])

    assert detect_password_spray(logs) == []


def test_same_user_does_not_trigger_password_spray():
    logs = make_logs([
        {
            "createdDateTime": f"2026-11-07T09:0{minute}:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        }
        for minute in range(3)
    ])

    assert detect_password_spray(logs) == []


# FAILURE-THEN-SUCCESS TEST

def test_failure_then_success_detected():
    events = []

    for minute in range(3):
        events.append({
            "createdDateTime": f"2026-11-07T09:0{minute}:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        })

    events.append({
        "createdDateTime": "2026-11-07T09:05:00Z",
        "userPrincipalName": "bob@demo.local",
        "ipAddress": "192.0.2.11",
        "status": "Success"
    })

    alerts = detect_failure_then_success(make_logs(events))

    assert len(alerts) == 1
    assert alerts[0]["alert_name"] == (
        "Successful Login After Repeated Failures"
    )


# REPORT GENERATION TESTS

def test_report_contains_all_alerts(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["total_alerts"] == 3
    assert len(report["alerts"]) == 3


def test_report_contains_investigation_guidance(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    first_alert = report["alerts"][0]

    assert "investigation_recommendations" in first_alert
    assert "recommended_actions" in first_alert
    assert len(first_alert["investigation_recommendations"]) > 0


# INVESTIGATION STATUS TESTS

def test_update_alert_status(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    result = update_alert_status(
        report_path,
        alert_id,
        "In Progress"
    )

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert result is True
    assert report["alerts"][0]["investigation_status"] == "In Progress"
    assert "last_updated" in report["alerts"][0]


def test_invalid_investigation_status(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    with pytest.raises(ValueError):
        update_alert_status(
            report_path,
            alert_id,
            "Invalid Status"
        )


def test_report_preserves_investigation_status(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    update_alert_status(
        report_path,
        alert_id,
        "In Progress"
    )

    generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["alerts"][0]["investigation_status"] == "In Progress"
    assert "last_updated" in report["alerts"][0]

    assert report["alerts"][1]["investigation_status"] == "Pending"
    assert report["alerts"][2]["investigation_status"] == "Pending"


# INPUT VALIDATION TESTS

def test_brute_force_invalid_timestamps():
    logs = make_logs([
        {
            "createdDateTime": "not-a-date",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        }
    ])

    alerts = detect_brute_force(logs)

    assert alerts == []


def test_brute_force_empty_logs():
    logs = pd.DataFrame(columns=[
        "createdDateTime",
        "userPrincipalName",
        "ipAddress",
        "status"
    ])

    alerts = detect_brute_force(logs)

    assert alerts == []


def test_brute_force_missing_user_and_ip():
    logs = make_logs([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": None,
            "ipAddress": None,
            "status": "Failure"
        }
    ])

    alerts = detect_brute_force(logs)

    assert alerts == []


# DUPLICATE-EVENT TESTS

def test_duplicate_events_do_not_trigger_brute_force():
    logs = make_logs([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:01:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:02:00Z",
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
            "createdDateTime": "2026-11-07T09:03:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "192.0.2.11",
            "status": "Failure"
        }
    ])

    alerts = detect_brute_force(logs)

    assert alerts == []


def test_duplicate_events_do_not_trigger_password_spray():
    logs = make_logs([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
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
            "createdDateTime": "2026-11-07T09:01:00Z",
            "userPrincipalName": "bob@demo.local",
            "ipAddress": "198.51.100.20",
            "status": "Failure"
        }
    ])

    alerts = detect_password_spray(logs)

    assert alerts == []


def test_duplicate_events_do_not_trigger_failure_then_success():
    logs = make_logs([
        {
            "createdDateTime": "2026-11-07T09:00:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "203.0.113.10",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:01:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "203.0.113.10",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:01:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "203.0.113.10",
            "status": "Failure"
        },
        {
            "createdDateTime": "2026-11-07T09:04:00Z",
            "userPrincipalName": "alice@demo.local",
            "ipAddress": "203.0.113.10",
            "status": "Success"
        }
    ])

    alerts = detect_failure_then_success(logs)

    assert alerts == []


def test_add_investigation_note(tmp_path):
    import json
    from src.reports.investigation_manager import add_investigation_note

    report_path = tmp_path / "alerts.json"

    report = {
        "alerts": [
            {
                "alert_id": "SOC-TEST-001",
                "investigation_status": "In Progress"
            }
        ]
    }

    report_path.write_text(json.dumps(report))

    result = add_investigation_note(
        report_path,
        "SOC-TEST-001",
        "SOC Analyst L1",
        "Reviewed authentication logs. Five failed attempts observed."
    )

    assert result is True

    saved_report = json.loads(report_path.read_text())
    alert = saved_report["alerts"][0]

    assert len(alert["investigation_notes"]) == 1
    assert alert["investigation_notes"][0]["analyst"] == "SOC Analyst L1"
    assert alert["investigation_notes"][0]["note"].startswith("Reviewed")
    assert "added_at" in alert["investigation_notes"][0]


def test_add_empty_investigation_note_fails(tmp_path):
    from src.reports.investigation_manager import add_investigation_note

    try:
        add_investigation_note(
            tmp_path / "alerts.json",
            "SOC-TEST-001",
            "SOC Analyst L1",
            ""
        )
        assert False, "Expected ValueError"
    except ValueError as error:
        assert "note cannot be empty" in str(error)


def test_add_note_to_unknown_alert_fails(tmp_path):
    import json
    from src.reports.investigation_manager import add_investigation_note

    report_path = tmp_path / "alerts.json"
    report_path.write_text(json.dumps({"alerts": []}))

    try:
        add_investigation_note(
            report_path,
            "SOC-UNKNOWN",
            "SOC Analyst L1",
            "Investigation started."
        )
        assert False, "Expected ValueError"
    except ValueError as error:
        assert "was not found" in str(error)

def test_add_investigation_note(tmp_path):
    import json
    from src.reports.investigation_manager import add_investigation_note

    report_path = tmp_path / "alerts.json"

    report = {
        "alerts": [
            {
                "alert_id": "SOC-TEST-001",
                "investigation_status": "In Progress"
            }
        ]
    }

    report_path.write_text(json.dumps(report))

    result = add_investigation_note(
        report_path,
        "SOC-TEST-001",
        "SOC Analyst L1",
        "Reviewed authentication logs. Five failed attempts observed."
    )

    assert result is True

    saved_report = json.loads(report_path.read_text())
    alert = saved_report["alerts"][0]

    assert len(alert["investigation_notes"]) == 1
    assert alert["investigation_notes"][0]["analyst"] == "SOC Analyst L1"
    assert alert["investigation_notes"][0]["note"].startswith("Reviewed")
    assert "added_at" in alert["investigation_notes"][0]


def test_add_empty_investigation_note_fails(tmp_path):
    from src.reports.investigation_manager import add_investigation_note

    try:
        add_investigation_note(
            tmp_path / "alerts.json",
            "SOC-TEST-001",
            "SOC Analyst L1",
            ""
        )
        assert False, "Expected ValueError"
    except ValueError as error:
        assert "note cannot be empty" in str(error)


def test_add_note_to_unknown_alert_fails(tmp_path):
    import json
    from src.reports.investigation_manager import add_investigation_note

    report_path = tmp_path / "alerts.json"
    report_path.write_text(json.dumps({"alerts": []}))

    try:
        add_investigation_note(
            report_path,
            "SOC-UNKNOWN",
            "SOC Analyst L1",
            "Investigation started."
        )
        assert False, "Expected ValueError"
    except ValueError as error:
        assert "was not found" in str(error)


# CLOSURE REASON TESTS

def test_resolved_status_requires_closure_reason(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    with pytest.raises(ValueError, match="closure reason is required"):
        update_alert_status(
            report_path,
            alert_id,
            "Resolved"
        )


def test_false_positive_status_requires_closure_reason(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    with pytest.raises(ValueError, match="closure reason is required"):
        update_alert_status(
            report_path,
            alert_id,
            "False Positive"
        )


def test_resolved_status_saves_closure_reason(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])
    reason = "Repeated failures investigated and resolved."

    # First move the alert to In Progress.
    update_alert_status(
        report_path,
        alert_id,
        "In Progress"
    )

    # Then resolve the alert.
    result = update_alert_status(
        report_path,
        alert_id,
        "Resolved",
        closure_reason=reason
    )

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    alert = report["alerts"][0]

    assert result is True
    assert alert["investigation_status"] == "Resolved"
    assert alert["closure_reason"] == reason
    assert alert["status_history"][-1]["closure_reason"] == reason

def test_false_positive_status_saves_closure_reason(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])
    reason = "Investigation confirmed legitimate user activity."

    # First move the alert to In Progress.
    update_alert_status(
        report_path,
        alert_id,
        "In Progress"
    )

    # Then mark it as False Positive.
    result = update_alert_status(
        report_path,
        alert_id,
        "False Positive",
        closure_reason=reason
    )

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    alert = report["alerts"][0]

    assert result is True
    assert alert["investigation_status"] == "False Positive"
    assert alert["closure_reason"] == reason
    assert alert["status_history"][-1]["closure_reason"] == reason

def test_pending_cannot_transition_directly_to_resolved(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    with pytest.raises(ValueError, match="Invalid status transition"):
        update_alert_status(
            report_path,
            alert_id,
            "Resolved",
            closure_reason="Investigation completed."
        )


def test_resolved_alert_cannot_be_reopened(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    update_alert_status(
        report_path,
        alert_id,
        "In Progress"
    )

    update_alert_status(
        report_path,
        alert_id,
        "Resolved",
        closure_reason="Investigation completed."
    )

    with pytest.raises(ValueError, match="Invalid status transition"):
        update_alert_status(
            report_path,
            alert_id,
            "In Progress"
        )


def test_false_positive_alert_cannot_be_reopened(tmp_path):
    alerts = make_sample_alerts()

    report_path = generate_alert_report(
        alerts,
        output_dir=tmp_path
    )

    alert_id = generate_alert_id(alerts[0])

    update_alert_status(
        report_path,
        alert_id,
        "In Progress"
    )

    update_alert_status(
        report_path,
        alert_id,
        "False Positive",
        closure_reason="Confirmed legitimate activity."
    )

    with pytest.raises(ValueError, match="Invalid status transition"):
        update_alert_status(
            report_path,
            alert_id,
            "Escalated"
        )
