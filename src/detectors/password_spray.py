
import pandas as pd

from src.ingestion.log_reader import load_signin_logs


def detect_password_spray(logs, threshold=3, window_minutes=10):
    """
    Detect an IP address with failed sign-ins
    against multiple distinct user accounts.
    """

    required_columns = [
        "createdDateTime",
        "userPrincipalName",
        "ipAddress",
        "status"
    ]

    for column in required_columns:
        if column not in logs.columns:
            raise ValueError(f"Missing column: {column}")

    logs = logs.drop_duplicates().copy()

    logs["createdDateTime"] = pd.to_datetime(
        logs["createdDateTime"],
        utc=True,
        errors="coerce"
    )

    logs = logs.dropna(
        subset=["createdDateTime", "userPrincipalName", "ipAddress"]
    )

    failed_logs = logs[
        logs["status"].astype(str).str.strip().str.lower() == "failure"
    ].copy()

    alerts = []

    for ip, group in failed_logs.groupby("ipAddress"):

        group = group.sort_values("createdDateTime")

        timestamps = group["createdDateTime"].tolist()
        users = group["userPrincipalName"].tolist()

        left = 0

        for right in range(len(timestamps)):

            while (
                timestamps[right] - timestamps[left]
            ).total_seconds() > window_minutes * 60:
                left += 1

            affected_users = sorted(set(users[left:right + 1]))

            if len(affected_users) >= threshold:
                alerts.append({
                    "alert_name": "Possible Password Spray",
                    "source_ip": ip,
                    "affected_users": affected_users,
                    "distinct_users": len(affected_users),
                    "first_attempt": timestamps[left],
                    "last_attempt": timestamps[right],
                    "severity": "High",
                    "mitre_technique": "T1110.003 - Password Spraying"
                })

                break

    return alerts


if __name__ == "__main__":

    logs = load_signin_logs("data/raw/signin_logs.csv")

    if logs is not None:

        alerts = detect_password_spray(logs)

        print("\nPassword Spray Detection Results")

        if alerts:
            for alert in alerts:
                print("\nALERT DETECTED")

                for key, value in alert.items():
                    print(f"{key}: {value}")
        else:
            print("No password spray indicators detected.")
