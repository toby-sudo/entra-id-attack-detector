import pandas as pd


def detect_failure_then_success(logs, failure_threshold=3, window_minutes=10):

    required_columns = [
        "createdDateTime",
        "userPrincipalName",
        "ipAddress",
        "status"
    ]

    if not all(column in logs.columns for column in required_columns):
        raise ValueError("Required columns are missing from sign-in logs.")

    logs = logs.drop_duplicates().copy()

    logs["createdDateTime"] = pd.to_datetime(
        logs["createdDateTime"], utc=True, errors="coerce"
    )

    logs["status"] = logs["status"].astype(str).str.lower()

    logs = logs.dropna(
        subset=["createdDateTime", "userPrincipalName", "ipAddress"]
    )

    alerts = []

    for (user, ip), group in logs.groupby(
        ["userPrincipalName", "ipAddress"]
    ):

        group = group.sort_values("createdDateTime")

        failures = group[group["status"] == "failure"]
        successes = group[group["status"] == "success"]

        for _, success in successes.iterrows():

            previous_failures = failures[
                (failures["createdDateTime"] < success["createdDateTime"]) &
                (
                    failures["createdDateTime"] >=
                    success["createdDateTime"] -
                    pd.Timedelta(minutes=window_minutes)
                )
            ]

            if len(previous_failures) >= failure_threshold:

                alerts.append({
                    "alert_name": "Successful Login After Repeated Failures",
                    "user": user,
                    "source_ip": ip,
                    "failed_attempts": len(previous_failures),
                    "first_failure": str(
                        previous_failures["createdDateTime"].min()
                    ),
                    "successful_login": str(success["createdDateTime"]),
                    "severity": "High",
                    "mitre_technique": "T1110 - Brute Force"
                })

                break

    return alerts
if __name__ == "__main__":
    from src.ingestion.log_reader import load_signin_logs

    logs = load_signin_logs("data/raw/signin_logs.csv")

    if logs is not None:
        alerts = detect_failure_then_success(logs)

        print("\nFailure-then-success alerts:")

        for alert in alerts:
            print(alert)