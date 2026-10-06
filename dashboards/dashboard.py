# -----------------------------------------
# Real-Time IDS Security Dashboard
# -----------------------------------------

import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st


# -----------------------------------------
# Page Configuration
# -----------------------------------------

st.set_page_config(
    page_title="Real-Time IDS Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# -----------------------------------------
# Database Location
# -----------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATABASE = PROJECT_ROOT / "data" / "security_alerts.db"


# -----------------------------------------
# Load Latest Alerts
# -----------------------------------------

def load_alerts():

    connection = sqlite3.connect(DATABASE)

    query = """
        SELECT
            id,
            timestamp,
            ip_address,
            username,
            alert_type,
            severity,
            description
        FROM alerts
        ORDER BY id DESC
    """

    dataframe = pd.read_sql_query(
        query,
        connection
    )

    connection.close()

    return dataframe


# -----------------------------------------
# Dashboard Header
# -----------------------------------------

st.title("🛡️ Real-Time Intrusion Detection System")

st.subheader(
    "Live Security Log Monitoring & Threat Detection Dashboard"
)

st.success("🟢 IDS Monitoring Active")

st.divider()


# -----------------------------------------
# Real-Time Dashboard
# -----------------------------------------

@st.fragment(run_every="3s")
def live_dashboard():

    # Load latest database records
    alerts = load_alerts()

    # -----------------------------------------
    # No Alerts
    # -----------------------------------------

    if alerts.empty:

        st.info(
            "🔎 No security alerts detected yet."
        )

        return


    # -----------------------------------------
    # Sidebar Filters
    # -----------------------------------------

    with st.sidebar:

        st.title("🔎 Filters")

        severity_options = sorted(
            alerts["severity"].dropna().unique()
        )

        selected_severity = st.multiselect(
            "Severity",
            severity_options,
            default=severity_options
        )


        alert_type_options = sorted(
            alerts["alert_type"].dropna().unique()
        )

        selected_alert_types = st.multiselect(
            "Alert Type",
            alert_type_options,
            default=alert_type_options
        )


        ip_options = sorted(
            alerts["ip_address"].dropna().unique()
        )

        selected_ips = st.multiselect(
            "IP Address",
            ip_options,
            default=ip_options
        )


        st.divider()

        st.caption(
            "Dashboard automatically refreshes every 3 seconds."
        )


    # -----------------------------------------
    # Apply Filters
    # -----------------------------------------

    filtered_alerts = alerts[
        alerts["severity"].isin(
            selected_severity
        )
        &
        alerts["alert_type"].isin(
            selected_alert_types
        )
        &
        alerts["ip_address"].isin(
            selected_ips
        )
    ]


    # -----------------------------------------
    # Security Metrics
    # -----------------------------------------

    total_alerts = len(filtered_alerts)

    high_alerts = len(
        filtered_alerts[
            filtered_alerts["severity"] == "HIGH"
        ]
    )

    medium_alerts = len(
        filtered_alerts[
            filtered_alerts["severity"] == "MEDIUM"
        ]
    )

    unique_ips = filtered_alerts[
        "ip_address"
    ].nunique()


    # -----------------------------------------
    # Metrics
    # -----------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "🚨 Total Alerts",
            total_alerts
        )

    with col2:

        st.metric(
            "🔴 High Severity",
            high_alerts
        )

    with col3:

        st.metric(
            "🟠 Medium Severity",
            medium_alerts
        )

    with col4:

        st.metric(
            "🌐 Suspicious IPs",
            unique_ips
        )


    st.divider()


    # -----------------------------------------
    # Live Status
    # -----------------------------------------

    st.markdown(
        "### 🟢 Live Monitoring"
    )

    st.caption(
        "New security alerts are automatically detected "
        "and displayed without manually refreshing the page."
    )


    # -----------------------------------------
    # Charts
    # -----------------------------------------

    col1, col2 = st.columns(2)


    with col1:

        st.subheader(
            "📊 Alerts by Type"
        )

        alert_type_counts = (
            filtered_alerts[
                "alert_type"
            ]
            .value_counts()
        )

        st.bar_chart(
            alert_type_counts
        )


    with col2:

        st.subheader(
            "⚠️ Severity Distribution"
        )

        severity_counts = (
            filtered_alerts[
                "severity"
            ]
            .value_counts()
        )

        st.bar_chart(
            severity_counts
        )


    st.divider()


    # -----------------------------------------
    # High Severity Warning
    # -----------------------------------------

    if high_alerts > 0:

        st.error(
            f"🚨 {high_alerts} HIGH severity "
            "security alert(s) detected!"
        )


    # -----------------------------------------
    # Security Alerts
    # -----------------------------------------

    st.subheader(
        "🚨 Security Alerts"
    )


    display_data = filtered_alerts[
        [
            "timestamp",
            "ip_address",
            "username",
            "alert_type",
            "severity",
            "description"
        ]
    ]


    st.dataframe(
        display_data,
        use_container_width=True,
        hide_index=True
    )


    # -----------------------------------------
    # Latest Alert
    # -----------------------------------------

    st.divider()

    latest_alert = filtered_alerts.iloc[0]

    st.subheader(
        "⚡ Latest Security Event"
    )

    st.info(
        f"""
**Time:** {latest_alert["timestamp"]}

**IP Address:** {latest_alert["ip_address"]}

**Username:** {latest_alert["username"]}

**Alert:** {latest_alert["alert_type"]}

**Severity:** {latest_alert["severity"]}

**Description:** {latest_alert["description"]}
"""
    )


# -----------------------------------------
# Start Live Dashboard
# -----------------------------------------

live_dashboard()


# -----------------------------------------
# Footer
# -----------------------------------------

st.divider()

st.caption(
    "Python-Based Real-Time Rule-Driven "
    "Intrusion Detection System"
)