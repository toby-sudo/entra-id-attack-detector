import json
from pathlib import Path
from datetime import datetime, timezone


VALID_STATUSES = [
    "Pending",
    "In Progress",
    "Escalated",
    "Resolved",
    "False Positive"
]
ALLOWED_TRANSITIONS = {
    "Pending": ["In Progress"],
    "In Progress": [
        "Escalated",
        "Resolved",
        "False Positive"
    ],
    "Escalated": [
        "In Progress",
        "Resolved",
        "False Positive"
    ],
    "Resolved": [],
    "False Positive": []
}
def update_alert_status(
    report_path,
    alert_id,
    new_status,
    closure_reason=None
):

    if new_status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status. Choose from: {VALID_STATUSES}"
        )

    # Require a reason when closing an alert.
    if new_status in ["Resolved", "False Positive"]:
        if not isinstance(closure_reason, str) or not closure_reason.strip():
            raise ValueError(
                f"A closure reason is required for status: {new_status}"
            )

    report_path = Path(report_path)

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    for alert in report.get("alerts", []):

        if alert.get("alert_id") != alert_id:
            continue

        timestamp = datetime.now(timezone.utc).isoformat()
        old_status = alert.get("investigation_status", "Pending")
        allowed_statuses = ALLOWED_TRANSITIONS.get(old_status, [])

        if new_status not in allowed_statuses:
            raise ValueError(
                f"Invalid status transition: {old_status} -> {new_status}. "
                f"Allowed transitions: {allowed_statuses}"
            )

        if "status_history" not in alert:
            alert["status_history"] = []

        history_entry = {
            "previous_status": old_status,
            "new_status": new_status,
            "changed_at": timestamp
        }

        if closure_reason is not None:
            history_entry["closure_reason"] = closure_reason.strip()
            alert["closure_reason"] = closure_reason.strip()

        alert["status_history"].append(history_entry)

        alert["investigation_status"] = new_status
        alert["last_updated"] = timestamp

        with open(report_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(
            f"Alert {alert_id} status updated to: {new_status}"
        )

        return True

    raise ValueError(f"Alert ID {alert_id} was not found.")


def add_investigation_note(report_path, alert_id, analyst, note):

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst name cannot be empty.")

    if not isinstance(note, str) or not note.strip():
        raise ValueError("Investigation note cannot be empty.")

    report_path = Path(report_path)

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    for alert in report.get("alerts", []):

        if alert.get("alert_id") != alert_id:
            continue

        timestamp = datetime.now(timezone.utc).isoformat()

        if "investigation_notes" not in alert:
            alert["investigation_notes"] = []

        alert["investigation_notes"].append({
            "analyst": analyst.strip(),
            "note": note.strip(),
            "added_at": timestamp
        })

        alert["last_updated"] = timestamp

        with open(report_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(f"Investigation note added to alert: {alert_id}")

        return True

    raise ValueError(f"Alert ID {alert_id} was not found.")
