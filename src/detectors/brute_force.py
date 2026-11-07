
import pandas as pd


def detect_brute_force(
    logs,
    threshold=5,
    window_minutes=10
):
    """
    Detect repeated failed sign-ins from the same
    IP address against the same user account.
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

    logs = logs.copy()

    logs["createdDateTime"] = pd.to_datetime(
        logs["createdDateTime"],
        utc=True,
        errors="coerce"
    )

    logs = logs.dropna(subset=["createdDateTime"])

    failed_logs = logs[
        logs["status"].str.lower() == "failure"
    ].copy()

    alerts = []

    for (user, ip), group in failed_logs.groupby(
        ["userPrincipalName", "ipAddress"]
    ):

        group = group.sort_values("createdDateTime")

        timestamps = group["createdDateTime"].tolist()

        left = 0

        for right in range(len(timestamps)):

            while (
                timestamps[right] - timestamps[left]
            ).total_seconds() > window_minutes * 60:

                left += 1

            attempt_count = right - left + 1

            if attempt_count >= threshold:

                alerts.append({
                    "alert_name": "Brute Force Login Attempt",
                    "user": user,
                    "source_ip": ip,
                    "failed_attempts": attempt_count,
                    "first_attempt": timestamps[left],
                    "last_attempt": timestamps[right],
                    "severity": "High",
                    "mitre_technique": "T1110 - Brute Force"
                })

                break

    return alerts


if __name__ == "__main__":

    from src.ingestion.log_reader import load_signin_logs

    logs = load_signin_logs(
        "data/raw/signin_logs.csv"
    )

    if logs is not None:

        alerts = detect_brute_force(logs)

        print("\nBrute Force Detection Results")

        if alerts:
            for alert in alerts:
                print("\nALERT DETECTED")

                for key, value in alert.items():
                    print(f"{key}: {value}")
        else:
            print("No brute-force activity detected.")
