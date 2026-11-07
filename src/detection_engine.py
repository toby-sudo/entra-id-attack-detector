
from src.ingestion.log_reader import load_signin_logs
from src.detectors.brute_force import detect_brute_force
from src.detectors.password_spray import detect_password_spray
from src.reports.report_generator import generate_alert_report


def run_detection_engine():

    print("=" * 55)
    print("       ENTRA ID SECURITY DETECTION ENGINE")
    print("=" * 55)

    logs = load_signin_logs("data/raw/signin_logs.csv")

    if logs is None:
        return

    all_alerts = []

    print("\nRunning brute-force detection...")
    brute_force_alerts = detect_brute_force(logs)
    all_alerts.extend(brute_force_alerts)

    print("Running password-spray detection...")
    password_spray_alerts = detect_password_spray(logs)
    all_alerts.extend(password_spray_alerts)

    print("\n" + "=" * 55)
    print("                 ALERT SUMMARY")
    print("=" * 55)

    if not all_alerts:
        print("No suspicious activity detected.")

    else:
        print(f"Total alerts generated: {len(all_alerts)}")

        for index, alert in enumerate(all_alerts, start=1):

            print(f"\nALERT #{index}")

            for key, value in alert.items():
                print(f"{key}: {value}")

        generate_alert_report(all_alerts)

    print("\n" + "=" * 55)
    print("Detection engine execution completed.")
    print("=" * 55)


if __name__ == "__main__":
    run_detection_engine()
