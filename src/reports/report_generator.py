
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

from src.reports.alert_classifier import classify_alert
def generate_alert_id(alert):

    identity = "|".join([
        str(alert.get("alert_name", "")),
        str(alert.get("user", "")),
        str(alert.get("source_ip", ""))
    ])

    fingerprint = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:12]

    return f"SOC-{fingerprint.upper()}"


def get_investigation_guidance(alert_name):

    guidance = {
        "Brute Force Login Attempt": {
            "investigation_recommendations": [
                "Review authentication logs for repeated failed attempts.",
                "Check whether the targeted account has privileged access.",
                "Review other accounts targeted by the same source IP."
            ],
            "recommended_actions": [
                "Validate the activity with the account owner.",
                "Review account security and authentication methods.",
                "Consider blocking the source IP if malicious activity is confirmed."
            ]
        },

        "Possible Password Spray": {
            "investigation_recommendations": [
                "Identify all accounts targeted by the source IP.",
                "Review authentication activity for the affected accounts.",
                "Check whether any targeted account had a successful login."
            ],
            "recommended_actions": [
                "Review affected accounts for suspicious activity.",
                "Check for additional authentication anomalies.",
                "Consider blocking the source IP if malicious activity is confirmed."
            ]
        },

        "Successful Login After Repeated Failures": {
            "investigation_recommendations": [
                "Verify the successful login with the account owner.",
                "Review the account's activity after the successful login.",
                "Check for suspicious access to applications or resources."
            ],
            "recommended_actions": [
                "Escalate the alert for analyst review.",
                "Consider resetting credentials if compromise is confirmed.",
                "Revoke active sessions if unauthorized access is confirmed."
            ]
        }
    }

    return guidance.get(alert_name, {
        "investigation_recommendations": [
            "Review the associated security events."
        ],
        "recommended_actions": [
            "Escalate for analyst review if suspicious activity is confirmed."
        ]
    })


def generate_alert_report(alerts, output_dir=None):

    if output_dir is None:
        project_root = Path(__file__).resolve().parents[2]
        output_dir = project_root / "data" / "processed"

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / "alerts.json"

    # Load the previous report to preserve investigation statuses.
    previous_alerts = {}

    if report_path.exists():

        try:
            with open(report_path, "r", encoding="utf-8") as file:
                previous_report = json.load(file)

            for old_alert in previous_report.get("alerts", []):
                previous_alerts[old_alert["alert_id"]] = old_alert

        except (json.JSONDecodeError, KeyError, TypeError):
            print("Warning: Previous report could not be read.")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": []
    }

    for alert in alerts:

        alert_id = alert.get("alert_id") or generate_alert_id(alert)

        classified_alert = classify_alert(alert)

        alert_record = dict(classified_alert)

        alert_record["alert_id"] = alert_id

        guidance = get_investigation_guidance(
            alert.get("alert_name", "")
        )

        alert_record.update(guidance)

        previous_alert = previous_alerts.get(alert_id, {})
        alert_record["investigation_status"] = previous_alert.get(
            "investigation_status", "Pending"
        )

        # Preserve investigation history and analyst work.
        for field in [
            "last_updated",
            "status_history",
            "investigation_notes",
            "closure_reason"
        ]:
            if field in previous_alert:
                alert_record[field] = previous_alert[field]


        report["alerts"].append(alert_record)

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, default=str)

    print(f"\nAlert report saved successfully: {report_path}")

    return report_path
