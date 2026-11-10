import json
from pathlib import Path


import pandas as pd
import plotly.express as px
import streamlit as _streamlit

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.reports.investigation_manager import update_alert_status, add_investigation_note


class _SidebarProxy:
    """Proxy for the streamlit sidebar with a useful fallback API."""

    def __getattr__(self, name):
        return getattr(_streamlit.sidebar, name)


class st:
    """Convenience wrapper around Streamlit that keeps dashboard calls stable."""

    def __init__(self):
        self.sidebar = _SidebarProxy()

    def __getattr__(self, name):
        attr = getattr(_streamlit, name, None)
        if attr is None:
            raise AttributeError(f"'st' object has no attribute '{name}'")
        return attr

    def set_page_config(self, *args, **kwargs):
        return _streamlit.set_page_config(*args, **kwargs)

    def title(self, *args, **kwargs):
        return _streamlit.title(*args, **kwargs)

    def caption(self, *args, **kwargs):
        return _streamlit.caption(*args, **kwargs)

    def divider(self, *args, **kwargs):
        return _streamlit.divider(*args, **kwargs)

    def subheader(self, *args, **kwargs):
        return _streamlit.subheader(*args, **kwargs)

    def warning(self, *args, **kwargs):
        return _streamlit.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        return _streamlit.error(*args, **kwargs)

    def write(self, *args, **kwargs):
        return _streamlit.write(*args, **kwargs)

    def columns(self, *args, **kwargs):
        return _streamlit.columns(*args, **kwargs)

    def metric(self, *args, **kwargs):
        return _streamlit.metric(*args, **kwargs)

    def info(self, *args, **kwargs):
        return _streamlit.info(*args, **kwargs)

    def markdown(self, *args, **kwargs):
        return _streamlit.markdown(*args, **kwargs)

    def plotly_chart(self, *args, **kwargs):
        """Render a Plotly figure in the dashboard."""
        return _streamlit.plotly_chart(*args, **kwargs)


st = st()


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUMMARY_FILE = PROJECT_ROOT / "data" / "processed" / "soc_summary.json"
ALERTS_FILE = PROJECT_ROOT / "data" / "processed" / "alerts.json"

# Page configuration
st.set_page_config(
    page_title="Entra ID SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# Load SOC summary
def load_soc_summary():
    if not SUMMARY_FILE.exists():
        return {}

    try:
        with open(SUMMARY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        st.error("Unable to read the SOC summary report.")
        return {}

def load_alerts():
    if not ALERTS_FILE.exists():
        return []

    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data.get("alerts", [])
    except (json.JSONDecodeError, OSError):
        st.error("Unable to read the alerts report.")
        return []

summary = load_soc_summary()
alerts = load_alerts()


# Dashboard header
st.title("🛡️ Entra ID Security Operations Center")
st.caption("Identity Threat Detection and Investigation Dashboard")

st.divider()


# Sidebar
st.sidebar.title("SOC Navigation")
st.sidebar.info("Dashboard Overview")

st.sidebar.markdown("---")
st.sidebar.write("Entra ID Attack Detection System")
st.sidebar.caption("Data source: Synthetic sign-in logs")


# Dashboard metrics
st.subheader("Security Overview")

if not summary:
    st.warning(
        "SOC summary report not found or empty. "
        "Run the detection engine and refresh the SOC reports."
    )
else:
    total_alerts = summary.get("total_alerts", 0)
    severity = summary.get("severity_distribution", {})
    status = summary.get("status_distribution", {})

    high_alerts = severity.get("High", 0)
    medium_alerts = severity.get("Medium", 0)
    low_alerts = severity.get("Low", 0)

    pending = status.get("Pending", 0)
    in_progress = status.get("In Progress", 0)
    escalated = status.get("Escalated", 0)
    resolved = status.get("Resolved", 0)
    false_positive = status.get("False Positive", 0)

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Alerts", total_alerts)
    col2.metric("High Severity", high_alerts)
    col3.metric("Medium Severity", medium_alerts)
    col4.metric("Low Severity", low_alerts)

    st.divider()

    st.subheader("Investigation Status")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Pending", pending)
    col2.metric("In Progress", in_progress)
    col3.metric("Escalated", escalated)
    col4.metric("Resolved", resolved)
    col5.metric("False Positive", false_positive)

    st.divider()

    st.subheader("Detection Summary")

    detection_distribution = summary.get(
        "detection_distribution", {}
    )

    if detection_distribution:
        for detection, count in detection_distribution.items():
            st.write(f"**{detection}:** {count}")
    st.divider()

    st.subheader("Security Analytics")

    col1, col2 = st.columns(2)

    # Chart 1: Alert severity
    with col1:
        severity_df = pd.DataFrame(
            list(severity.items()),
            columns=["Severity", "Count"]
        )

        fig_severity = px.pie(
            severity_df,
            names="Severity",
            values="Count",
            hole=0.45,
            title="Alert Distribution by Severity"
        )

        st.plotly_chart(
            fig_severity,
            use_container_width=True
        )

    # Chart 2: Investigation status
    with col2:
        status_df = pd.DataFrame(
            list(status.items()),
            columns=["Status", "Count"]
        )

        fig_status = px.bar(
            status_df,
            x="Status",
            y="Count",
            text="Count",
            title="Investigation Status Distribution"
        )

        st.plotly_chart(
            fig_status,
            use_container_width=True
        )

st.divider()

# Alerts Management
st.divider()
st.header("🚨 Alert Management")

if not alerts:
    st.info("No alerts are available.")
else:
    alert_rows = []

    for alert in alerts:
        affected_users = alert.get("affected_users", [])

        if alert.get("user"):
            affected_users.append(alert["user"])

        alert_rows.append({
            "Alert ID": alert.get("alert_id", "N/A"),
            "Alert Name": alert.get("alert_name", "N/A"),
            "Severity": alert.get("severity", "Unknown"),
            "Status": alert.get("investigation_status", "Unknown"),
            "Detection Type": alert.get("mitre_technique", "N/A"),
            "Source IP": alert.get("source_ip", "N/A"),
            "Affected Users": ", ".join(affected_users),
            "Failed Attempts": alert.get("failed_attempts", 0)
        })

    alerts_df = pd.DataFrame(alert_rows)

    # Search
    search_term = st.text_input(
        "Search alerts",
        placeholder="Search by alert name, ID, user, or IP..."
    )

    # Filters
    filter_col1, filter_col2, filter_col3 = st.columns(3)

    with filter_col1:
        severity_options = sorted(alerts_df["Severity"].unique())
        selected_severity = st.multiselect(
            "Filter by Severity",
            severity_options,
            default=severity_options
        )

    with filter_col2:
        status_options = sorted(alerts_df["Status"].unique())
        selected_status = st.multiselect(
            "Filter by Status",
            status_options,
            default=status_options
        )

    with filter_col3:
        detection_options = sorted(
            alerts_df["Detection Type"].unique()
        )
        selected_detection = st.multiselect(
            "Filter by Detection Type",
            detection_options,
            default=detection_options
        )

    # Apply filters
    filtered_df = alerts_df[
        alerts_df["Severity"].isin(selected_severity)
        & alerts_df["Status"].isin(selected_status)
        & alerts_df["Detection Type"].isin(selected_detection)
    ]

    # Apply search
    if search_term:
        search_mask = filtered_df.astype(str).apply(
            lambda row: row.str.contains(
                search_term,
                case=False,
                regex=False
            ).any(),
            axis=1
        )
        filtered_df = filtered_df[search_mask]

    st.caption(f"Showing {len(filtered_df)} of {len(alerts_df)} alerts")

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

# Investigation Workspace
st.divider()
st.header("🔍 Investigation Workspace")

if alerts:
    alert_ids = [
        alert.get("alert_id")
        for alert in alerts
        if alert.get("alert_id")
    ]

    selected_alert_id = st.selectbox(
        "Select an alert to investigate",
        alert_ids
    )

    selected_alert = next(
        alert for alert in alerts
        if alert.get("alert_id") == selected_alert_id
    )

    st.subheader(selected_alert.get("alert_name", "Unknown Alert"))

    detail_col1, detail_col2, detail_col3 = st.columns(3)

    detail_col1.metric(
        "Severity",
        selected_alert.get("severity", "Unknown")
    )

    detail_col2.metric(
        "Investigation Status",
        selected_alert.get("investigation_status", "Unknown")
    )

    detail_col3.metric(
        "Evidence Completeness",
        f"{selected_alert.get('evidence_completeness_score', 0)}%"
    )

    st.write("**Alert ID:**", selected_alert_id)
    st.write("**Source IP:**", selected_alert.get("source_ip", "N/A"))
    st.write("**MITRE Technique:**", selected_alert.get("mitre_technique", "N/A"))

    affected_users = selected_alert.get("affected_users", [])

    if selected_alert.get("user"):
        affected_users = affected_users + [selected_alert["user"]]

    st.write("**Affected Users:**", ", ".join(affected_users) or "N/A")

    st.write("**Severity Reason:**")
    st.info(selected_alert.get("severity_reason", "No reason available."))

    with st.expander("View Complete Alert Evidence"):
        st.json(selected_alert)

    st.subheader("Investigation Notes")

    st.subheader("Update Investigation Status")

    current_status = selected_alert.get(
        "investigation_status", "Pending"
    )

    allowed_transitions = {
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

    available_statuses = allowed_transitions.get(
        current_status, []
    )

    if available_statuses:
        new_status = st.selectbox(
            "New Investigation Status",
            available_statuses,
            key=f"status_{selected_alert_id}"
        )

        closure_reason = ""

        if new_status in ["Resolved", "False Positive"]:
            closure_reason = st.text_area(
                "Closure Reason (Required)",
                key=f"closure_{selected_alert_id}"
            )

        if st.button("Update Status"):
            try:
                update_alert_status(
                    ALERTS_FILE,
                    selected_alert_id,
                    new_status,
                    closure_reason=closure_reason or None
                )
                st.success("Investigation status updated.")
                st.rerun()

            except (ValueError, OSError, json.JSONDecodeError) as error:
                st.error(str(error))
    else:
        st.info(
            f"This alert is currently {current_status}. "
            "No further status transitions are allowed."
        )


    analyst_name = st.text_input(
        "Analyst Name",
        placeholder="Enter analyst name"
    )

    investigation_note = st.text_area(
        "Investigation Note",
        placeholder="Describe your findings, evidence, and actions taken..."
    )

    if st.button("Save Investigation Note"):
        try:
            src.reports.investigation_manager.add_investigation_note(
                ALERTS_FILE,
                selected_alert_id,
                analyst_name,
                investigation_note
            )
            st.success("Investigation note saved successfully.")
            st.rerun()

        except (ValueError, OSError, json.JSONDecodeError) as error:
            st.error(str(error))

else:
    st.info("No alerts available for investigation.")


st.caption(
    "Entra ID Attack Detection & Investigation System | "
    "SOC Dashboard | Synthetic Data"
)
