import json
import pytest

from src.reports.soc_summary import (
    load_alerts,
    generate_soc_summary,
    generate_unresolved_alert_report,
    generate_investigation_evidence_report,
    save_soc_summary,
    save_unresolved_alert_report,
    save_investigation_evidence_report,
    generate_and_save_soc_summary,
    refresh_all_soc_reports,
)


@pytest.fixture
def sample_alerts(tmp_path):

    alerts = {
        "alerts": [
            {
                "alert_id": "SOC-001",
                "alert_name": "Brute Force Login Attempt",
                "severity": "Medium",
                "investigation_status": "Escalated",
                "user": "alice@demo.local",
                "source_ip": "192.0.2.10",
                "failed_attempts": 5,
                "investigation_notes": [{"analyst": "Analyst 1", "note": "Reviewed"}],
                "status_history": []
            },
            {
                "alert_id": "SOC-002",
                "alert_name": "Possible Password Spray",
                "severity": "Medium",
                "investigation_status": "Resolved",
                "user": "Multiple users",
                "source_ip": "198.51.100.20"
            },
            {
                "alert_id": "SOC-003",
                "alert_name": "Successful Login After Repeated Failures",
                "severity": "High",
                "investigation_status": "Pending",
                "user": "bob@demo.local",
                "source_ip": "192.0.2.11",
                "failed_attempts": 5
            }
        ]
    }

    report_path = tmp_path / "alerts.json"

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(alerts, file)

    return report_path


def test_load_alerts(sample_alerts):

    alerts = load_alerts(sample_alerts)

    assert len(alerts) == 3


def test_load_alerts_missing_file(tmp_path):

    missing_path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_alerts(missing_path)


def test_generate_soc_summary(sample_alerts):

    summary = generate_soc_summary(sample_alerts)

    assert summary["total_alerts"] == 3
    assert summary["severity_distribution"] == {
        "Medium": 2,
        "High": 1
    }
    assert summary["pending_alerts"] == 1
    assert summary["escalated_alerts"] == 1
    assert summary["resolved_alerts"] == 1
    assert summary["false_positive_alerts"] == 0


def test_generate_unresolved_alert_report(sample_alerts):

    report = generate_unresolved_alert_report(sample_alerts)

    assert report["total_unresolved_alerts"] == 2
    assert len(report["pending_alerts"]) == 1
    assert len(report["escalated_alerts"]) == 1

    assert report["pending_alerts"][0]["alert_id"] == "SOC-003"
    assert report["escalated_alerts"][0]["alert_id"] == "SOC-001"


def test_generate_investigation_evidence_report(sample_alerts):

    report = generate_investigation_evidence_report(sample_alerts)

    assert report["total_investigations"] == 3

    investigation = report["investigations"][0]

    assert investigation["alert_id"] == "SOC-001"
    assert investigation["detection_evidence"]["failed_attempts"] == 5
    assert investigation["investigation"]["current_status"] == "Escalated"
    assert len(investigation["investigation"]["analyst_notes"]) == 1


def test_save_soc_summary(tmp_path):

    summary = {"total_alerts": 3}
    output_path = tmp_path / "reports" / "summary.json"

    saved_path = save_soc_summary(summary, output_path)

    assert saved_path.exists()

    with open(saved_path, "r", encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data["total_alerts"] == 3

def test_save_unresolved_alert_report(tmp_path):

    report = {
        "total_unresolved_alerts": 1,
        "pending_alerts": [{"alert_id": "SOC-001"}],
        "escalated_alerts": []
    }

    output_path = tmp_path / "reports" / "unresolved.json"

    saved_path = save_unresolved_alert_report(report, output_path)

    assert saved_path.exists()

    with open(saved_path, "r", encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data["total_unresolved_alerts"] == 1


def test_save_investigation_evidence_report(tmp_path):

    report = {
        "total_investigations": 1,
        "investigations": [{"alert_id": "SOC-001"}]
    }

    output_path = tmp_path / "reports" / "evidence.json"

    saved_path = save_investigation_evidence_report(report, output_path)

    assert saved_path.exists()

    with open(saved_path, "r", encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data["total_investigations"] == 1


def test_generate_and_save_soc_summary(sample_alerts, tmp_path):

    output_path = tmp_path / "reports" / "summary.json"

    saved_path = generate_and_save_soc_summary(
        sample_alerts,
        output_path
    )

    assert saved_path.exists()

    with open(saved_path, "r", encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data["total_alerts"] == 3
    assert saved_data["pending_alerts"] == 1


def test_refresh_all_soc_reports(tmp_path, monkeypatch):

    import src.reports.soc_summary as soc_module

    project_root = tmp_path

    processed_dir = project_root / "data" / "processed"
    processed_dir.mkdir(parents=True)

    alerts = {
        "alerts": [
            {
                "alert_id": "SOC-001",
                "alert_name": "Brute Force Login Attempt",
                "severity": "Medium",
                "investigation_status": "Pending",
                "user": "alice@demo.local",
                "source_ip": "192.0.2.10",
                "failed_attempts": 5
            }
        ]
    }

    alert_path = processed_dir / "alerts.json"

    with open(alert_path, "w", encoding="utf-8") as file:
        json.dump(alerts, file)

    fake_module_path = (
        project_root / "src" / "reports" / "soc_summary.py"
    )

    monkeypatch.setattr(
        soc_module,
        "__file__",
        str(fake_module_path)
    )

    refresh_all_soc_reports()

    assert (processed_dir / "soc_summary.json").exists()
    assert (processed_dir / "unresolved_alerts.json").exists()
    assert (processed_dir / "investigation_evidence.json").exists()
