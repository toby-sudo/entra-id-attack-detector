from pprint import pformat
from src.reports.soc_summary import refresh_all_soc_reports
from src.reports.investigation_manager import update_alert_status
from src.reports.investigation_manager import add_investigation_note
import json
from pathlib import Path

def view_all_alerts():
    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "alerts.json"

    if not report_path.exists():
        print("\nNo alert report found.")
        return

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    alerts = report.get("alerts", [])

    if not alerts:
        print("\nNo alerts available.")
        return

    print("\n" + "=" * 70)
    print("                         SOC ALERTS")
    print("=" * 70)

    for alert in alerts:
        alert_id = alert.get("alert_id", "Unknown ID")
        severity = alert.get("severity", "Unknown")
        status = alert.get("investigation_status", "Pending")
        title = alert.get("alert_name", "Unknown Alert")
        user = alert.get("user", "N/A")
        source_ip = alert.get("source_ip", "N/A")

        print(f"\nAlert ID:  {alert_id}")
        print(f"Alert:     {title}")
        print(f"Severity:  {severity}")
        print(f"Status:    {status}")
        print(f"User:      {user}")
        print(f"Source IP: {source_ip}")
        print("-" * 70)

    print("\n" + "=" * 70)
    print(f"Total Alerts: {len(alerts)}")
    print("=" * 70)



def view_alert_details():

    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "alerts.json"

    if not report_path.exists():
        print("\nNo alert report found.")
        return

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    alerts = report.get("alerts", [])

    if not alerts:
        print("\nNo alerts available.")
        return

    alert_id = input("\nEnter Alert ID: ").strip()

    selected_alert = next(
        (
            alert for alert in alerts
            if alert.get("alert_id") == alert_id
        ),
        None
    )

    if selected_alert is None:
        print("\nAlert ID not found.")
        return

    print("\n" + "=" * 65)
    print("             ALERT INVESTIGATION DETAILS")
    print("=" * 65)
    for key, value in selected_alert.items():

        print(f"\n{key.replace('_', ' ').title()}:")

        if isinstance(value, list):
            if value and isinstance(value[0], dict):
                print(pformat(value, indent=4, sort_dicts=False))
            else:
                for item in value:
                    print(f"- {item}")
        elif isinstance(value, dict):
            print(pformat(value, indent=4, sort_dicts=False))
        else:
            print(value)

def add_note():
    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "alerts.json"

    if not report_path.exists():
        print("\nNo alert report found.")
        return

    alert_id = input("\nEnter Alert ID: ").strip()
    analyst = input("Enter Analyst Name: ").strip()
    note = input("Enter Investigation Note: ").strip()

    try:
        result = add_investigation_note(
            report_path,
            alert_id,
            analyst,
            note
        )

        if result:
            print("\nInvestigation note recorded successfully.")

    except ValueError as error:
        print(f"\nError: {error}")


def update_status():
    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "alerts.json"

    if not report_path.exists():
        print("\nNo alert report found.")
        return

    alert_id = input("\nEnter Alert ID: ").strip()
    status = input("Enter new status: ").strip()
    if not alert_id or not status:
        print("\nAlert ID and status are required.")
        return

    try:
        result = update_alert_status(report_path, alert_id, status)
        if result:
            print("\nAlert status updated successfully.")
        else:
            print("\nAlert status could not be updated. Check the Alert ID.")
    except ValueError as error:
        print(f"\nError: {error}")

def resolve_alert():

    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "alerts.json"

    alert_id = input("\nEnter Alert ID: ").strip()

    closure_reason = input(
        "\nEnter resolution reason: "
    ).strip()

    if not closure_reason:
        print("\nResolution reason cannot be empty.")
        return

    try:
        update_alert_status(
            report_path,
            alert_id,
            "Resolved",
            closure_reason=closure_reason
        )

        print("\nAlert resolved successfully.")

    except ValueError as error:
        print(f"\nError: {error}")

def view_investigation_history():

    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "alerts.json"

    if not report_path.exists():
        print("\nNo alert report found.")
        return

    with open(report_path, "r", encoding="utf-8") as file:
        report_data = json.load(file)

    alerts = report_data.get("alerts", [])

    alert_id = input("\nEnter Alert ID: ").strip()

    alert = next(
        (item for item in alerts if item.get("alert_id") == alert_id),
        None
    )

    if alert is None:
        print("\nAlert ID not found.")
        return

    print("\n=============================================")
    print("          INVESTIGATION HISTORY")
    print("=============================================")

    print(f"\nAlert ID: {alert_id}")
    print(f"Alert Name: {alert.get('alert_name', 'N/A')}")
    print(f"Current Status: {alert.get('investigation_status', 'Pending')}")

    print("\n--- STATUS HISTORY ---")

    status_history = alert.get("status_history", [])

    if not status_history:
        print("No status changes recorded.")
    else:
        for entry in status_history:
            print(f"\nPrevious Status: {entry.get('previous_status', 'N/A')}")
            print(f"New Status: {entry.get('new_status', 'N/A')}")
            print(f"Changed At: {entry.get('changed_at', 'N/A')}")

            if entry.get("closure_reason"):
                print(f"Closure Reason: {entry['closure_reason']}")

    print("\n--- INVESTIGATION NOTES ---")

    notes = alert.get("investigation_notes", [])

    if not notes:
        print("No investigation notes recorded.")
    else:
        for index, note in enumerate(notes, start=1):
            print(f"\nNote {index}")
            print(f"Analyst: {note.get('analyst', 'N/A')}")
            print(f"Note: {note.get('note', 'N/A')}")
            print(f"Added At: {note.get('added_at', 'N/A')}")

    print("\n=============================================")

def view_soc_summary():

    project_root = Path(__file__).resolve().parents[2]
    summary_path = project_root / "data" / "processed" / "soc_summary.json"

    if not summary_path.exists():
        print("\nSOC summary report not found.")
        print("Generate the summary report first.")
        return

    with open(summary_path, "r", encoding="utf-8") as file:
        summary = json.load(file)

    print("\n" + "=" * 60)
    print("              SOC INVESTIGATION SUMMARY")
    print("=" * 60)

    print(f"\nTotal Alerts: {summary.get('total_alerts', 0)}")

    print("\n--- SEVERITY DISTRIBUTION ---")

    for severity, count in summary.get(
        "severity_distribution", {}
    ).items():
        print(f"{severity}: {count}")

    print("\n--- INVESTIGATION STATUS ---")

    for status, count in summary.get(
        "status_distribution", {}
    ).items():
        print(f"{status}: {count}")

    print("\n--- DETECTION TYPE DISTRIBUTION ---")

    for detection, count in summary.get(
        "detection_distribution", {}
    ).items():
        print(f"{detection}: {count}")

    print("\n--- INVESTIGATION OVERVIEW ---")

    print(f"Pending Alerts: {summary.get('pending_alerts', 0)}")
    print(f"Escalated Alerts: {summary.get('escalated_alerts', 0)}")
    print(f"Resolved Alerts: {summary.get('resolved_alerts', 0)}")
    print(f"False Positive Alerts: {summary.get('false_positive_alerts', 0)}")

    print("\n" + "=" * 60)

def view_unresolved_alerts():
    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "unresolved_alerts.json"

    if not report_path.exists():
        print("\nUnresolved alert report not found.")
        print("Generate the report first.")
        return

    try:
        with open(report_path, "r", encoding="utf-8") as file:
            report = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"\nUnable to read unresolved alert report: {error}")
        return

    if not isinstance(report, dict):
        print("\nUnresolved alert report has an invalid format.")
        return

    status_groups = {
        "pending_alerts": report.get("pending_alerts", []),
        "escalated_alerts": report.get("escalated_alerts", []),
    }
    total = sum(len(alerts) for alerts in status_groups.values()
                if isinstance(alerts, list))

    print("\n" + "=" * 65)
    print("              UNRESOLVED ALERT REPORT")
    print("=" * 65)

    print(f"\nTotal Unresolved Alerts: {report.get('total_unresolved_alerts', total)}")

    for status, alerts in status_groups.items():
        print(f"\n--- {status.replace('_', ' ').upper()} ---")

        if not isinstance(alerts, list) or not alerts:
            print("No alerts found.")
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            print(f"\nAlert ID: {alert.get('alert_id', 'N/A')}")
            print(f"Alert: {alert.get('alert_name', 'N/A')}")
            print(f"Severity: {alert.get('severity', 'N/A')}")
            print(f"User: {alert.get('user', 'N/A')}")
            print(f"Source IP: {alert.get('source_ip', 'N/A')}")

            print("\nRecommended Actions:")

            actions = alert.get("recommended_actions", [])
            if isinstance(actions, list) and actions:
                for action in actions:
                    print(f"- {action}")
            else:
                print("No recommended actions provided.")

            print("-" * 65)

    print("\n" + "=" * 65)

def view_investigation_evidence():

    project_root = Path(__file__).resolve().parents[2]

    report_path = (
        project_root
        / "data"
        / "processed"
        / "investigation_evidence.json"
    )

    if not report_path.exists():
        print("\nInvestigation evidence report not found.")
        return

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    print("\n" + "=" * 65)
    print("          INVESTIGATION EVIDENCE REPORT")
    print("=" * 65)

    print(f"\nTotal Investigations: {report.get('total_investigations', 0)}")

    for investigation in report.get("investigations", []):

        print("\n" + "-" * 65)

        print(f"Alert ID: {investigation.get('alert_id')}")
        print(f"Alert: {investigation.get('alert_name')}")
        print(f"Severity: {investigation.get('severity')}")
        print(f"MITRE Technique: {investigation.get('mitre_technique')}")

        print("\n--- DETECTION EVIDENCE ---")

        for key, value in investigation.get(
            "detection_evidence", {}
        ).items():
            print(f"{key.replace('_', ' ').title()}: {value}")

        print("\n--- INVESTIGATION STATUS ---")

        details = investigation.get("investigation", {})

        print(f"Current Status: {details.get('current_status')}")

        print("\n--- ANALYST NOTES ---")

        notes = details.get("analyst_notes", [])

        if not notes:
            print("No investigation notes recorded.")

        for note in notes:
            print(f"Analyst: {note.get('analyst')}")
            print(f"Note: {note.get('note')}")
            print(f"Added At: {note.get('added_at')}")

        print("\n--- CLOSURE REASON ---")
        print(details.get("closure_reason") or "Not closed")

    print("\n" + "=" * 65)


def escalate_alert():

    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "data" / "processed" / "alerts.json"

    alert_id = input("\nEnter Alert ID: ").strip()

    try:
        update_alert_status(
            report_path,
            alert_id,
            "Escalated"
        )

        print("\nAlert escalated successfully.")

    except ValueError as error:
        print(f"\nError: {error}")



def display_menu():
    print("\n" + "=" * 45)
    print("          SOC ALERT MANAGEMENT")
    print("=" * 45)

    print("1. View All Alerts")
    print("2. View Alert Details")
    print("3. Add Investigation Note")
    print("4. Update Alert Status")
    print("5. Escalate Alert")
    print("6. Resolve Alert")
    print("7. View Investigation History")
    print("8. Exit")
    print("9. View SOC Summary Report")
    print("10. View Unresolved Alert Report")
    print("11. View Investigation Evidence Report")
    print("12. Refresh All SOC Reports")

    print("=" * 45)



def main():

    while True:

        display_menu()

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            view_all_alerts()

        elif choice == "2":
            view_alert_details()

        elif choice == "3":
            add_note()

        elif choice == "4":
            update_status()

        elif choice == "5":
            escalate_alert()

        elif choice == "6":
            resolve_alert()

        elif choice == "7":
            view_investigation_history()

        elif choice == "8":
            print("\nExiting SOC Alert Management.")
            break
        elif choice == "9":
            view_soc_summary()
            input("\n Press Enter to return to the menu...")

        elif choice == "10":
            view_unresolved_alerts()
            input("\nPress Enter to return to the menu...")

        elif choice == "11":
            view_investigation_evidence()
            input("\n Press Enter to return to the menu...")

        elif choice == "12":
            try:
                refresh_all_soc_reports()
            except FileNotFoundError as error:
                print(f"\nError: {error}")

        else:
            print("\nInvalid choice. Please select 1-12.")



if __name__ == "__main__":
    main()
