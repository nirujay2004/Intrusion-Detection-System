import streamlit as st
import sqlite3
import pandas as pd


# -----------------------------------------
# Configuration
# -----------------------------------------

DATABASE = "data/security_alerts.db"


# -----------------------------------------
# Page configuration
# -----------------------------------------

st.set_page_config(
    page_title="Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)


# -----------------------------------------
# Page title
# -----------------------------------------

st.title("🛡️ Intrusion Detection System")
st.subheader("Security Log Monitoring Dashboard")


# -----------------------------------------
# Connect to database
# -----------------------------------------

connection = sqlite3.connect(DATABASE)


# -----------------------------------------
# Read alerts
# -----------------------------------------

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


alerts = pd.read_sql_query(
    query,
    connection
)


connection.close()


# -----------------------------------------
# Dashboard statistics
# -----------------------------------------

total_alerts = len(alerts)

high_alerts = len(
    alerts[alerts["severity"] == "HIGH"]
)

medium_alerts = len(
    alerts[alerts["severity"] == "MEDIUM"]
)

unique_ips = alerts["ip_address"].nunique()


# -----------------------------------------
# Display statistics
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


# -----------------------------------------
# Alert table
# -----------------------------------------

st.divider()

st.header("🚨 Security Alerts")


st.dataframe(
    alerts,
    use_container_width=True,
    hide_index=True
)