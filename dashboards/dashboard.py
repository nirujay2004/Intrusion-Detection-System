# -----------------------------------------
# IDS Security Operations Center
# -----------------------------------------

import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


# -----------------------------------------
# Page Configuration
# -----------------------------------------

st.set_page_config(
    page_title="IDS Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# -----------------------------------------
# Custom CSS
# -----------------------------------------

st.markdown(
    """
<style>

.stApp {
    background-color: #0b0f14;
    color: #e6edf3;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1450px;
}

h1 {
    font-size: 2rem !important;
    font-weight: 700 !important;
}

h2, h3 {
    font-weight: 600 !important;
}

.metric-card {
    background: #111820;
    border: 1px solid #26313d;
    border-radius: 8px;
    padding: 18px 20px;
    min-height: 115px;
}

.metric-label {
    color: #8b98a7;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-value {
    color: #f0f6fc;
    font-size: 2rem;
    font-weight: 700;
    margin-top: 8px;
}

.metric-description {
    color: #657384;
    font-size: 0.75rem;
    margin-top: 5px;
}

.status-online {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: #0d281c;
    border: 1px solid #1d5c3b;
    color: #4ade80;
    padding: 7px 13px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
}

.status-dot {
    width: 8px;
    height: 8px;
    background: #22c55e;
    border-radius: 50%;
}

.section-header {
    font-size: 0.78rem;
    font-weight: 700;
    color: #8b98a7;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-top: 20px;
    margin-bottom: 12px;
}

.latest-alert {
    background: #111820;
    border: 1px solid #26313d;
    border-radius: 8px;
    padding: 20px;
}

.latest-title {
    font-size: 1rem;
    font-weight: 700;
    color: #f0f6fc;
}

.latest-detail {
    color: #9aa7b5;
    font-size: 0.82rem;
    margin-top: 10px;
}

section[data-testid="stSidebar"] {
    background-color: #0d131a;
    border-right: 1px solid #202a35;
}

#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

</style>
""",
    unsafe_allow_html=True
)


# -----------------------------------------
# Database
# -----------------------------------------

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

DATABASE = (
    PROJECT_ROOT
    / "data"
    / "security_alerts.db"
)


# -----------------------------------------
# Load Alerts
# -----------------------------------------

def load_alerts():

    connection = sqlite3.connect(
        DATABASE
    )

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

header_left, header_right = st.columns(
    [5, 1]
)

with header_left:

    st.title(
        "Intrusion Detection & Response"
    )

    st.caption(
        "Real-time authentication threat monitoring"
    )


with header_right:

    st.markdown(
        """
        <div style="text-align:right; margin-top:15px;">
        <span class="status-online">
        <span class="status-dot"></span>
        SYSTEM ONLINE
        </span>
        </div>
        """,
        unsafe_allow_html=True
    )


st.divider()


# -----------------------------------------
# Live Dashboard
# -----------------------------------------

@st.fragment(run_every="3s")
def live_dashboard():

    alerts = load_alerts()


    # -----------------------------------------
    # Empty State
    # -----------------------------------------

    if alerts.empty:

        st.info(
            "No security events detected. "
            "Monitoring is active."
        )

        return


    # -----------------------------------------
    # Sidebar
    # -----------------------------------------

    with st.sidebar:

        st.markdown(
            "### Monitoring Controls"
        )

        st.caption(
            "Filters apply to the live alert stream."
        )

        st.divider()

        severity_options = sorted(
            alerts["severity"]
            .dropna()
            .unique()
        )

        selected_severity = st.multiselect(
            "Severity",
            severity_options,
            default=severity_options
        )

        attack_options = sorted(
            alerts["alert_type"]
            .dropna()
            .unique()
        )

        selected_attacks = st.multiselect(
            "Detection Type",
            attack_options,
            default=attack_options
        )

        ip_options = sorted(
            alerts["ip_address"]
            .dropna()
            .unique()
        )

        selected_ips = st.multiselect(
            "Source IP",
            ip_options,
            default=ip_options
        )

        st.divider()

        st.caption(
            "Automatic refresh: 3 seconds"
        )


    # -----------------------------------------
    # Apply Filters
    # -----------------------------------------

    filtered = alerts[
        alerts["severity"].isin(
            selected_severity
        )
        &
        alerts["alert_type"].isin(
            selected_attacks
        )
        &
        alerts["ip_address"].isin(
            selected_ips
        )
    ]


    # -----------------------------------------
    # Metrics
    # -----------------------------------------

    total_alerts = len(filtered)

    high_alerts = len(
        filtered[
            filtered["severity"] == "HIGH"
        ]
    )

    medium_alerts = len(
        filtered[
            filtered["severity"] == "MEDIUM"
        ]
    )

    unique_sources = (
        filtered["ip_address"].nunique()
    )


    # -----------------------------------------
    # KPI Cards
    # -----------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.markdown(
            f'<div class="metric-card"><div class="metric-label">TOTAL ALERTS</div><div class="metric-value">{total_alerts}</div><div class="metric-description">Detected security events</div></div>',
            unsafe_allow_html=True
        )

    with col2:

        st.markdown(
            f'<div class="metric-card"><div class="metric-label">HIGH SEVERITY</div><div class="metric-value">{high_alerts}</div><div class="metric-description">Immediate attention</div></div>',
            unsafe_allow_html=True
        )

    with col3:

        st.markdown(
            f'<div class="metric-card"><div class="metric-label">MEDIUM SEVERITY</div><div class="metric-value">{medium_alerts}</div><div class="metric-description">Suspicious activity</div></div>',
            unsafe_allow_html=True
        )

    with col4:

        st.markdown(
            f'<div class="metric-card"><div class="metric-label">UNIQUE SOURCES</div><div class="metric-value">{unique_sources}</div><div class="metric-description">Source IP addresses</div></div>',
            unsafe_allow_html=True
        )


    # -----------------------------------------
    # Threat Analytics
    # -----------------------------------------

    st.markdown(
        '<div class="section-header">THREAT ANALYTICS</div>',
        unsafe_allow_html=True
    )


    chart1, chart2 = st.columns(2)


    # -----------------------------------------
    # Attack Type Chart
    # -----------------------------------------

    with chart1:

        attack_counts = (
            filtered["alert_type"]
            .value_counts()
            .reset_index()
        )

        attack_counts.columns = [
            "Attack Type",
            "Count"
        ]

        figure = px.bar(
            attack_counts,
            x="Attack Type",
            y="Count",
            text="Count"
        )

        figure.update_layout(
            template="plotly_dark",
            paper_bgcolor="#111820",
            plot_bgcolor="#111820",
            font=dict(
                color="#c9d1d9"
            ),
            margin=dict(
                l=20,
                r=20,
                t=50,
                b=20
            ),
            title="Detections by Attack Type"
        )

        figure.update_traces(
            marker_color="#3b82f6"
        )

        st.plotly_chart(
            figure,
            use_container_width=True
        )


    # -----------------------------------------
    # Severity Chart
    # -----------------------------------------

    with chart2:

        severity_counts = (
            filtered["severity"]
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        figure = px.pie(
            severity_counts,
            names="Severity",
            values="Count",
            hole=0.55
        )

        figure.update_layout(
            template="plotly_dark",
            paper_bgcolor="#111820",
            plot_bgcolor="#111820",
            font=dict(
                color="#c9d1d9"
            ),
            margin=dict(
                l=20,
                r=20,
                t=50,
                b=20
            ),
            title="Severity Distribution"
        )

        st.plotly_chart(
            figure,
            use_container_width=True
        )


    # -----------------------------------------
    # Active Alerts
    # -----------------------------------------

    st.markdown(
        '<div class="section-header">ACTIVE SECURITY ALERTS</div>',
        unsafe_allow_html=True
    )

    table_data = filtered[
        [
            "timestamp",
            "ip_address",
            "username",
            "alert_type",
            "severity",
            "description"
        ]
    ].copy()

    table_data.columns = [
        "Timestamp",
        "Source IP",
        "Username",
        "Detection",
        "Severity",
        "Description"
    ]

    st.dataframe(
        table_data,
        use_container_width=True,
        hide_index=True,
        height=350
    )


    # -----------------------------------------
    # Latest Detection
    # -----------------------------------------

    if not filtered.empty:

        latest = filtered.iloc[0]

        st.markdown(
            '<div class="section-header">LATEST DETECTION</div>',
            unsafe_allow_html=True
        )

        if latest["severity"] == "HIGH":

            border_color = "#ef4444"

        else:

            border_color = "#f59e0b"


        latest_html = (
            '<div class="latest-alert" '
            f'style="border-left:4px solid {border_color};">'
            '<div class="latest-title">'
            f'{latest["alert_type"]} | {latest["severity"]}'
            '</div>'
            '<div class="latest-detail">'
            f'<b>Source:</b> {latest["ip_address"]}'
            '&nbsp;&nbsp;&nbsp;'
            f'<b>Account:</b> {latest["username"]}'
            '&nbsp;&nbsp;&nbsp;'
            f'<b>Detected:</b> {latest["timestamp"]}'
            '</div>'
            '<div class="latest-detail">'
            f'{latest["description"]}'
            '</div>'
            '</div>'
        )

        st.markdown(
            latest_html,
            unsafe_allow_html=True
        )


# -----------------------------------------
# Run Dashboard
# -----------------------------------------

live_dashboard()


# -----------------------------------------
# Footer
# -----------------------------------------

st.divider()

st.caption(
    "Real-Time Rule-Based Intrusion Detection System"
    " • Monitoring interval: 3 seconds"
)