
from src.reports.alert_classifier import classify_alert


def test_brute_force_classification():
    alert = {
        "alert_name": "Brute Force Login Attempt",
        "user": "alice@example.com",
        "source_ip": "192.0.2.10",
        "failed_attempts": 5,
        "first_attempt": "2026-11-07T09:00:00Z",
        "last_attempt": "2026-11-07T09:05:00Z"
    }

    result = classify_alert(alert)

    assert result["severity"] == "Medium"
    assert result["evidence_completeness_score"] == 100
    assert result["evidence_completeness_level"] == "High"


def test_password_spray_classification():
    alert = {
        "alert_name": "Possible Password Spray",
        "source_ip": "198.51.100.20",
        "affected_users": [
            "alice@example.com",
            "bob@example.com",
            "carol@example.com"
        ],
        "distinct_users": 3,
        "first_attempt": "2026-11-07T09:00:00Z",
        "last_attempt": "2026-11-07T09:05:00Z"
    }

    result = classify_alert(alert)

    assert result["severity"] == "Medium"
    assert result["evidence_completeness_score"] == 100
    assert result["evidence_completeness_level"] == "High"


def test_failure_then_success_classification():
    alert = {
        "alert_name": "Successful Login After Repeated Failures",
        "user": "alice@example.com",
        "source_ip": "192.0.2.10",
        "failed_attempts": 5,
        "first_failure": "2026-11-07T09:00:00Z",
        "successful_login": "2026-11-07T09:05:00Z"
    }

    result = classify_alert(alert)

    assert result["severity"] == "High"
    assert result["evidence_completeness_score"] == 100
    assert result["evidence_completeness_level"] == "High"


def test_missing_evidence_reduces_confidence():
    alert = {
        "alert_name": "Brute Force Login Attempt",
        "user": "alice@example.com",
        "source_ip": "192.0.2.10",
        "failed_attempts": 5
    }

    result = classify_alert(alert)

    assert result["severity"] == "Medium"
    assert result["evidence_completeness_score"] == 60
    assert result["evidence_completeness_level"] == "Medium"


def test_unknown_alert_type():
    alert = {
        "alert_name": "Unknown Detection"
    }

    result = classify_alert(alert)

    assert result["severity"] == "Low"
    assert result["evidence_completeness_score"] == 0
    assert result["evidence_completeness_level"] == "Low"
