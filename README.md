# Entra ID Attack Detection & Investigation System

A Python-based Security Operations Center (SOC) project that analyzes synthetic Microsoft Entra ID sign-in logs, detects suspicious authentication patterns, classifies security alerts, and supports structured security investigations.

## Project Overview

This project simulates an identity-focused SOC detection and investigation workflow.

It processes sign-in log data, identifies suspicious authentication activities, generates security alerts, and provides tools for analysts to investigate, document, escalate, and resolve incidents.

**Important:** This project uses synthetic sign-in logs. It does not connect to a live Microsoft Entra ID tenant or Microsoft Graph API.

## Key Features

- CSV-based sign-in log ingestion using Pandas.
- Brute-force login detection.
- Possible password-spray detection.
- Successful login after repeated failures detection.
- Automated alert classification and severity assignment.
- Evidence completeness assessment.
- MITRE ATT&CK technique mapping.
- Unique SOC alert ID generation.
- Investigation status management.
- Analyst investigation notes and status history.
- Alert escalation and resolution with closure reasons.
- SOC summary reporting.
- Unresolved alert reporting.
- Investigation evidence reporting.
- Command-line interface for alert management.
- Interactive Streamlit SOC dashboard.
- Searchable alerts with severity, status, and detection filters.
- Interactive security analytics using Plotly charts.
- Investigation workspace with alert evidence viewing.
- Dashboard-based investigation notes and status updates.
- Automated unit testing using Pytest.

## Detection Capabilities

| Detection | Description | MITRE ATT&CK |
|---|---|---|
| Brute Force | Identifies repeated failed login attempts against an account from the same IP. | T1110 |
| Possible Password Spray | Identifies one source IP attempting authentication against multiple accounts. | T1110.003 |
| Failure Followed by Success | Identifies a successful login after repeated failures for the same account and IP. | T1110 |

These detections identify suspicious patterns and do not independently establish that an account has been compromised.

## Alert Classification

The system assigns severity based on the detection type:

- **Medium:** Brute-force login attempts.
- **Medium:** Possible password-spray activity.
- **High:** Successful login following repeated failures.

It also calculates an evidence completeness score based on the expected fields available for each detection.

Evidence completeness measures the presence of expected evidence fields; it is not an attack probability or confidence score.

## Investigation Management

The investigation workflow supports five statuses:

1. Pending
2. In Progress
3. Escalated
4. Resolved
5. False Positive

Additional capabilities:

- Add analyst investigation notes.
- Maintain investigation status history.
- Require closure reasons for resolved and false-positive alerts.
- Preserve investigation information when reports are regenerated.
- Prevent invalid status transitions and reopening of closed alerts.

## SOC Reporting

The project generates three reports:

**1. SOC Summary Report**
- Total alerts.
- Severity distribution.
- Investigation status distribution.
- Detection type distribution.
- Pending, escalated, resolved, and false-positive counts.

**2. Unresolved Alert Report**
- Pending and escalated alerts.
- Alert identification details.
- Recommended investigation actions.

**3. Investigation Evidence Report**
- Detection evidence.
- Severity reasoning.
- Evidence completeness.
- Analyst notes.
- Investigation history.
- Recommended actions.

Generated reports are stored in `data/processed/`.

## Technology Stack

- Python 3.12
- Pandas
- Streamlit
- Plotly
- JSON
- CSV
- Pytest
- Git and GitHub

## Project Structure

```text
entra-id-attack-detector/
│
├── data/
│   ├── raw/
│   │   └── signin_logs.csv
│   │
│   └── processed/
│       ├── alerts.json
│       ├── soc_summary.json
│       ├── unresolved_alerts.json
│       └── investigation_evidence.json
│
├── src/
│   ├── ingestion/
│   │   └── log_reader.py
│   │
│   ├── detectors/
│   │   ├── brute_force.py
│   │   ├── password_spray.py
│   │   └── failure_then_success.py
│   │
│   ├── reports/
│   │   ├── alert_classifier.py
│   │   ├── report_generator.py
│   │   ├── investigation_manager.py
│   │   └── soc_summary.py
│   │
│   ├── cli/
│   │   └── alert_manager.py
│   │
│   ├── dashboard/
│   │   ├── __init__.py
│   │   └── app.py
│   │
│   └── detection_engine.py
│
├── tests/
│   ├── test_detection.py
│   ├── test_alert_classifier.py
│   └── test_soc_summary.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/toby-sudo/entra-id-attack-detector.git
cd entra-id-attack-detector
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

### 3. Activate the virtual environment

macOS / Linux:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

### Run the detection engine

```bash
python -m src.detection_engine
```

This loads the synthetic sign-in logs, executes all three detection modules, classifies alerts, and generates the alert report.

### Launch the SOC alert management CLI

```bash
python -m src.cli.alert_manager
```

The CLI supports viewing alerts, adding investigation notes, changing statuses, escalating alerts, resolving incidents, viewing reports, and refreshing SOC reports.

### Launch the SOC Dashboard

```bash
streamlit run src/dashboard/app.py
```

Open `http://localhost:8501` in your browser.

The dashboard provides alert analytics, searchable alert records, investigation notes, and status management.

### Run automated tests

```bash
python -m pytest -v
```

**Current test results:** 44 tests passed.

## Sample Detection Scenarios

The included synthetic dataset demonstrates:

- Five failed authentication attempts against one account from a single IP.
- Failed authentication attempts against three different accounts from one IP.
- A successful login following repeated failures for the same account and IP.

The dataset uses documentation-only IP addresses and fictional user accounts.

## Project Limitations

- Uses synthetic authentication logs rather than live Entra ID telemetry.
- Does not integrate with Microsoft Graph API.
- Does not perform automatic account blocking or remediation.
- Does not include MFA, device-risk, geolocation-risk, or post-login activity analysis.
- Detection results require analyst validation.

## Future Enhancements

- Microsoft Graph API integration for real Entra ID sign-in logs.
- Additional identity-based attack detection rules.
- MFA fatigue and suspicious MFA activity detection.
- Risk-based alert prioritization.
- Microsoft Graph API integration for real Entra ID sign-in logs.
- Additional identity-based attack detection rules.
- MFA fatigue and suspicious MFA activity detection.
- Risk-based alert prioritization.
- SIEM integration and automated incident response.
- SIEM integration and automated incident response.

## Author

Developed as a cybersecurity portfolio project focused on identity threat detection, SOC operations, and security investigation workflows.