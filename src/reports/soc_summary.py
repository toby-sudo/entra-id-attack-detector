import json
import collections
from pathlib import Path

def load_alerts(report_path):

    report_path = Path(report_path)

    if not report_path.exists():
        raise FileNotFoundError(
            f"Alert report not found: {report_path}"
        )

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    return report.get("alerts", [])


def generate_soc_summary(report_path):

    alerts = load_alerts(report_path)

    total_alerts = len(alerts)

    severity_counts = collections.Counter(
        alert.get("severity", "Unknown")
        for alert in alerts
    )

    status_counts = collections.Counter(
        alert.get("investigation_status", "Pending")
        for alert in alerts
    )

    detection_counts = collections.Counter(
        alert.get("alert_name", "Unknown")
        for alert in alerts
    )

    pending_alerts = sum(
        alert.get("investigation_status", "Pending") == "Pending"
        for alert in alerts
    )

    escalated_alerts = sum(
        alert.get("investigation_status") == "Escalated"
        for alert in alerts
    )

    resolved_alerts = sum(
        alert.get("investigation_status") == "Resolved"
        for alert in alerts
    )

    false_positive_alerts = sum(
        alert.get("investigation_status") == "False Positive"
        for alert in alerts
    )

    summary = {
        "total_alerts": total_alerts,
        "severity_distribution": dict(severity_counts),
        "status_distribution": dict(status_counts),
        "detection_distribution": dict(detection_counts),
        "pending_alerts": pending_alerts,
        "escalated_alerts": escalated_alerts,
        "resolved_alerts": resolved_alerts,
        "false_positive_alerts": false_positive_alerts
    }
    return summary
def save_soc_summary(summary, output_path=None):

    if output_path is None:
        project_root = Path(__file__).resolve().parents[2]
        output_path = project_root / "data" / "processed" / "soc_summary.json"

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=4)

    print(f"\nSOC summary report saved: {output_path}")

    return output_path


def generate_and_save_soc_summary(report_path, output_path=None):

    summary = generate_soc_summary(report_path)

    saved_path = save_soc_summary(
        summary,
        output_path
    )

    return saved_path

def generate_unresolved_alert_report(report_path):

    alerts = load_alerts(report_path)

    unresolved_statuses = ["Pending", "Escalated"]

    unresolved_alerts = [
        alert for alert in alerts
        if alert.get("investigation_status", "Pending")
        in unresolved_statuses
    ]

    report = {
        "total_unresolved_alerts": len(unresolved_alerts),
        "pending_alerts": [],
        "escalated_alerts": []
    }

    for alert in unresolved_alerts:

        alert_details = {
            "alert_id": alert.get("alert_id", "N/A"),
            "alert_name": alert.get("alert_name", "N/A"),
            "severity": alert.get("severity", "Unknown"),
            "user": alert.get("user", "N/A"),
            "source_ip": alert.get("source_ip", "N/A"),
            "recommended_actions": alert.get(
                "recommended_actions", []
            )
        }

        status = alert.get("investigation_status", "Pending")

        if status == "Pending":
            report["pending_alerts"].append(alert_details)

        elif status == "Escalated":
            report["escalated_alerts"].append(alert_details)

    return report

def save_unresolved_alert_report(report, output_path=None):

    if output_path is None:
        project_root = Path(__file__).resolve().parents[2]
        output_path = (
            project_root
            / "data"
            / "processed"
            / "unresolved_alerts.json"
        )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nUnresolved alert report saved: {output_path}")

    return output_path

def generate_investigation_evidence_report(report_path):

    alerts = load_alerts(report_path)

    investigation_reports = []

    for alert in alerts:

        evidence = {
            "alert_id": alert.get("alert_id", "N/A"),
            "alert_name": alert.get("alert_name", "N/A"),
            "severity": alert.get("severity", "Unknown"),
            "severity_reason": alert.get("severity_reason", "N/A"),
            "mitre_technique": alert.get("mitre_technique", "N/A"),
            "detection_evidence": {
                "user": alert.get("user", "N/A"),
                "source_ip": alert.get("source_ip", "N/A"),
                "failed_attempts": alert.get("failed_attempts", "N/A"),
                "affected_users": alert.get("affected_users", []),
                "distinct_users": alert.get("distinct_users", "N/A"),
                "first_attempt": alert.get(
                    "first_attempt", alert.get("first_failure", "N/A")
                ),
                "last_attempt": alert.get(
                    "last_attempt", alert.get("successful_login", "N/A")
                ),
                "first_failure": alert.get("first_failure", "N/A"),
                "successful_login": alert.get("successful_login", "N/A")
            },

            "evidence_completeness": {
                "score": alert.get("evidence_completeness_score", "N/A"),
                "level": alert.get("evidence_completeness_level", "N/A"),
                "reason": alert.get("evidence_completeness_reason", "N/A")
            },

            "investigation": {
                "current_status": alert.get(
                    "investigation_status", "Pending"
                ),
                "analyst_notes": alert.get("investigation_notes", []),
                "status_history": alert.get("status_history", []),
                "closure_reason": alert.get("closure_reason", None)
            },

            "investigation_recommendations": alert.get(
                "investigation_recommendations", []
            ),

            "recommended_actions": alert.get(
                "recommended_actions", []
            )
        }

        investigation_reports.append(evidence)

    return {
        "total_investigations": len(investigation_reports),
        "investigations": investigation_reports
    }

def save_investigation_evidence_report(report, output_path=None):

    if output_path is None:
        project_root = Path(__file__).resolve().parents[2]
        output_path = (
            project_root
            / "data"
            / "processed"
            / "investigation_evidence.json"
        )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nInvestigation evidence report saved: {output_path}")

    return output_path

def refresh_all_soc_reports():

    project_root = Path(__file__).resolve().parents[2]

    alert_path = (
        project_root / "data" / "processed" / "alerts.json"
    )

    if not alert_path.exists():
        raise FileNotFoundError("Main alert report not found.")

    # Generate SOC summary
    summary = generate_soc_summary(alert_path)
    save_soc_summary(summary)

    # Generate unresolved alert report
    unresolved = generate_unresolved_alert_report(alert_path)
    save_unresolved_alert_report(unresolved)

    # Generate investigation evidence report
    evidence = generate_investigation_evidence_report(alert_path)
    save_investigation_evidence_report(evidence)

    print("\nAll SOC reports refreshed successfully.")
