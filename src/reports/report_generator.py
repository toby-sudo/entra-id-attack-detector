
import json
from pathlib import Path
from datetime import datetime, timezone


def generate_alert_report(alerts):

    project_root = Path(__file__).resolve().parents[2]

    output_dir = project_root / "data" / "processed"
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / "alerts.json"

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": []
    }

    for index, alert in enumerate(alerts, start=1):

        report["alerts"].append({
            "alert_id": f"SOC-{index:04d}",
            "alert_name": alert["alert_name"],
            "severity": alert["severity"],
            "source_ip": alert["source_ip"],
            "mitre_technique": alert["mitre_technique"],
            "details": {
                key: str(value)
                for key, value in alert.items()
            },
            "investigation_status": "Pending"
        })

    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nAlert report saved successfully: {report_path}")

    return report_path
