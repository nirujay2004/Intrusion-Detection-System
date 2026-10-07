import os
import html

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


# Configuration
API_URL = (
    os.getenv("IDS_API_URL")
    or os.getenv("API_URL")
    or "http://127.0.0.1:8000"
).rstrip("/")

REFRESH_SECONDS = 3


# Page configuration
st.set_page_config(
    page_title="IDS Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Custom styling
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

    .status-online,
    .status-offline {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 7px 13px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .status-online {
        background: #0d281c;
        border: 1px solid #1d5c3b;
        color: #4ade80;
    }

    .status-offline {
        background: #2a1111;
        border: 1px solid #6b2020;
        color: #f87171;
    }

    .status-dot,
    .status-dot-offline {
        width: 8px;
        height: 8px;
        border-radius: 50%;
    }

    .status-dot {
        background: #22c55e;
    }

    .status-dot-offline {
        background: #ef4444;
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

    #MainMenu,
    footer {
        visibility: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def api_get(endpoint: str):
    """Request data from the FastAPI backend."""
    url = f"{API_URL}/{endpoint.lstrip('/')}"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.Timeout:
        return {"error": f"Request timed out while connecting to {url}"}

    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to FastAPI at {url}"}

    except requests.exceptions.RequestException as error:
        return {"error": str(error)}

    except ValueError:
        return {"error": "FastAPI returned an invalid JSON response."}


def load_alerts():
    data = api_get("/alerts")

    if "error" in data:
        return pd.DataFrame(), data["error"]

    alerts = data.get("alerts", [])

    if not alerts:
        return pd.DataFrame(), None

    dataframe = pd.DataFrame(alerts)

    required_columns = [
        "id",
        "timestamp",
        "ip_address",
        "username",
        "alert_type",
        "severity",
        "description",
    ]

    for column in required_columns:
        if column not in dataframe.columns:
            dataframe[column] = ""

    if "id" in dataframe.columns:
        dataframe = dataframe.sort_values(
            by="id",
            ascending=False,
            kind="stable",
        )

    return dataframe.reset_index(drop=True), None


def load_stats():
    data = api_get("/stats")

    if "error" in data:
        return None, data["error"]

    return data, None


# Header
header_left, header_right = st.columns([5, 1])

with header_left:
    st.title("Intrusion Detection & Response")
    st.caption("Real-time rule-based network intrusion monitoring")

with header_right:
    health = api_get("/health")

    if "error" not in health:
        st.markdown(
            """
            <div style="text-align:right; margin-top:15px;">
                <span class="status-online">
                    <span class="status-dot"></span>
                    SYSTEM ONLINE
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="text-align:right; margin-top:15px;">
                <span class="status-offline">
                    <span class="status-dot-offline"></span>
                    API OFFLINE
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.divider()


@st.fragment(run_every=f"{REFRESH_SECONDS}s")
def live_dashboard():
    alerts, alert_error = load_alerts()
    stats, stats_error = load_stats()

    # Sidebar filters
    with st.sidebar:
        st.markdown("### Monitoring Controls")
        st.caption("Filters apply to the live IDS alert stream.")
        st.divider()

        if alerts.empty:
            selected_severity = []
            selected_attacks = []
            selected_ips = []
            st.info("No alerts available yet.")
        else:
            severity_options = sorted(
                alerts["severity"].dropna().astype(str).unique().tolist()
            )

            attack_options = sorted(
                alerts["alert_type"].dropna().astype(str).unique().tolist()
            )

            ip_options = sorted(
                alerts["ip_address"].dropna().astype(str).unique().tolist()
            )

            selected_severity = st.multiselect(
                "Severity",
                severity_options,
                default=severity_options,
            )

            selected_attacks = st.multiselect(
                "Detection Type",
                attack_options,
                default=attack_options,
            )

            selected_ips = st.multiselect(
                "Source IP",
                ip_options,
                default=ip_options,
            )

        st.divider()
        st.caption(f"Automatic refresh: {REFRESH_SECONDS} seconds")
        st.caption(f"Backend: {API_URL}")

    # Backend status
    if alert_error:
        st.error("FastAPI backend is unavailable.")
        st.code(f"Backend: {API_URL}\nError: {alert_error}")
        st.info("Start FastAPI with: uvicorn api.main:app --reload")
        return

    if stats_error:
        st.warning("Alert data is available, but statistics could not be loaded.")

    # Empty state
    if alerts.empty:
        st.info(
            "No security alerts detected yet. "
            "IDS monitoring is active and waiting for events."
        )
        st.markdown(
            """
            ### Test the pipeline

            Run the event generator in another terminal:

            ```text
            python src/event_generator.py
            ```

            Then select an attack simulation.
            """
        )
        return

    # Apply filters
    filtered = alerts[
        alerts["severity"].astype(str).isin(selected_severity)
        & alerts["alert_type"].astype(str).isin(selected_attacks)
        & alerts["ip_address"].astype(str).isin(selected_ips)
    ].copy()

    # Metrics
    total_alerts = len(filtered)
    high_alerts = int((filtered["severity"] == "HIGH").sum())
    medium_alerts = int((filtered["severity"] == "MEDIUM").sum())
    unique_sources = int(filtered["ip_address"].nunique())

    # KPI cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">TOTAL ALERTS</div>
                <div class="metric-value">{total_alerts}</div>
                <div class="metric-description">Detected security events</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">HIGH SEVERITY</div>
                <div class="metric-value">{high_alerts}</div>
                <div class="metric-description">Immediate attention</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">MEDIUM SEVERITY</div>
                <div class="metric-value">{medium_alerts}</div>
                <div class="metric-description">Suspicious activity</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">UNIQUE SOURCES</div>
                <div class="metric-value">{unique_sources}</div>
                <div class="metric-description">Source IP addresses</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Threat analytics
    st.markdown(
        '<div class="section-header">THREAT ANALYTICS</div>',
        unsafe_allow_html=True,
    )

    chart1, chart2 = st.columns(2)

    with chart1:
        attack_counts = (
            filtered["alert_type"]
            .value_counts()
            .reset_index()
        )
        attack_counts.columns = ["Attack Type", "Count"]

        if not attack_counts.empty:
            figure = px.bar(
                attack_counts,
                x="Attack Type",
                y="Count",
                text="Count",
            )

            figure.update_layout(
                template="plotly_dark",
                paper_bgcolor="#111820",
                plot_bgcolor="#111820",
                font=dict(color="#c9d1d9"),
                margin=dict(l=20, r=20, t=50, b=20),
                title="Detections by Attack Type",
            )

            figure.update_traces(marker_color="#3b82f6")

            st.plotly_chart(
                figure,
                width="stretch",
                config={"displayModeBar": False},
            )
        else:
            st.info("No attack data matches the filters.")

    with chart2:
        severity_counts = (
            filtered["severity"]
            .value_counts()
            .reset_index()
        )
        severity_counts.columns = ["Severity", "Count"]

        if not severity_counts.empty:
            figure = px.pie(
                severity_counts,
                names="Severity",
                values="Count",
                hole=0.55,
            )

            figure.update_layout(
                template="plotly_dark",
                paper_bgcolor="#111820",
                plot_bgcolor="#111820",
                font=dict(color="#c9d1d9"),
                margin=dict(l=20, r=20, t=50, b=20),
                title="Severity Distribution",
            )

            st.plotly_chart(
                figure,
                width="stretch",
                config={"displayModeBar": False},
            )
        else:
            st.info("No severity data matches the filters.")

    # Active alerts
    st.markdown(
        '<div class="section-header">ACTIVE SECURITY ALERTS</div>',
        unsafe_allow_html=True,
    )

    if filtered.empty:
        st.info("No alerts match the current filters.")
        return

    table_data = filtered[
        [
            "timestamp",
            "ip_address",
            "username",
            "alert_type",
            "severity",
            "description",
        ]
    ].copy()

    table_data.columns = [
        "Timestamp",
        "Source IP",
        "Username",
        "Detection",
        "Severity",
        "Description",
    ]

    st.dataframe(
        table_data,
        width="stretch",
        hide_index=True,
        height=350,
    )

    # Latest detection
    latest = filtered.iloc[0]

    st.markdown(
        '<div class="section-header">LATEST DETECTION</div>',
        unsafe_allow_html=True,
    )

    severity = str(latest["severity"]).upper()

    if severity == "HIGH":
        border_color = "#ef4444"
    elif severity == "MEDIUM":
        border_color = "#f59e0b"
    else:
        border_color = "#64748b"

    alert_type = html.escape(str(latest["alert_type"]))
    severity_text = html.escape(str(latest["severity"]))
    ip_address = html.escape(str(latest["ip_address"]))
    username = html.escape(str(latest["username"]))
    timestamp = html.escape(str(latest["timestamp"]))
    description = html.escape(str(latest["description"]))

    latest_html = (
        f'<div class="latest-alert" style="border-left:4px solid {border_color};">'
        f'<div class="latest-title">{alert_type} | {severity_text}</div>'
        f'<div class="latest-detail"><b>Source:</b> {ip_address}'
        f'&nbsp;&nbsp;&nbsp;<b>Account:</b> {username}'
        f'&nbsp;&nbsp;&nbsp;<b>Detected:</b> {timestamp}</div>'
        f'<div class="latest-detail">{description}</div>'
        f'</div>'
    )

    st.markdown(latest_html, unsafe_allow_html=True)


live_dashboard()


st.divider()

st.caption(
    "Real-Time Rule-Based Network Intrusion Detection System"
    " • FastAPI Backend"
    " • SQLite Alert Store"
    f" • Monitoring interval: {REFRESH_SECONDS} seconds"
)
