import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st


# -----------------------------------------
# Page Configuration
# -----------------------------------------

st.set_page_config(
    page_title="IDS Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# -----------------------------------------
# Database
# -----------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATABASE = PROJECT_ROOT / "data" / "security_alerts.db"


# -----------------------------------------
# Load Alerts
# -----------------------------------------

@st.cache_data
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
# Header
# -----------------------------------------

st.title("🛡️ Intrusion Detection System")

st.subheader(
    "Security Log Monitoring & Threat Detection Dashboard"
)

st.divider()


# -----------------------------------------
# Load Data
# -----------------------------------------

alerts = load_alerts()


if alerts.empty:

    st.warning("No security alerts found.")

    st.stop()


# -----------------------------------------
# Sidebar Filters
# -----------------------------------------

st.sidebar.title("🔎 Filters")


# Severity filter

severity_options = sorted(
    alerts["severity"].unique()
)

selected_severity = st.sidebar.multiselect(
    "Severity",
    severity_options,
    default=severity_options
)


# Alert type filter

alert_type_options = sorted(
    alerts["alert_type"].unique()
)

selected_alert_types = st.sidebar.multiselect(
    "Alert Type",
    alert_type_options,
    default=alert_type_options
)


# IP filter

ip_options = sorted(
    alerts["ip_address"].unique()
)

selected_ips = st.sidebar.multiselect(
    "IP Address",
    ip_options,
    default=ip_options
)


# Refresh button

if st.sidebar.button("🔄 Refresh Data"):

    st.cache_data.clear()

    st.rerun()


# -----------------------------------------
# Apply Filters
# -----------------------------------------

filtered_alerts = alerts[
    alerts["severity"].isin(selected_severity)
    &
    alerts["alert_type"].isin(selected_alert_types)
    &
    alerts["ip_address"].isin(selected_ips)
]


# -----------------------------------------
# Metrics
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
# Charts
# -----------------------------------------

col1, col2 = st.columns(2)


with col1:

    st.subheader("📊 Alerts by Type")

    alert_type_counts = (
        filtered_alerts["alert_type"]
        .value_counts()
    )

    st.bar_chart(
        alert_type_counts
    )


with col2:

    st.subheader("⚠️ Severity Distribution")

    severity_counts = (
        filtered_alerts["severity"]
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

st.subheader("🚨 Security Alerts")


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
# Footer
# -----------------------------------------

st.divider()

st.caption(
    "Python-Based Rule-Driven Intrusion Detection System"
)