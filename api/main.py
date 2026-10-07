from datetime import datetime
from pathlib import Path
import sqlite3

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.detection_engine import DetectionEngine
from src.database import save_alert


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="Real-Time IDS API",
    description="Security Event Ingestion and Intrusion Detection API",
    version="1.0.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DATABASE
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATABASE = PROJECT_ROOT / "data" / "security_alerts.db"


# =========================================================
# DETECTION ENGINE
# =========================================================

detector = DetectionEngine()


# =========================================================
# AUTHENTICATION EVENT SCHEMA
# =========================================================

class SecurityEvent(BaseModel):
    ip_address: str
    username: str
    status: str


# =========================================================
# NETWORK IDS ALERT SCHEMA
# =========================================================

class NetworkAlert(BaseModel):
    timestamp: str
    ip_address: str
    username: str
    alert_type: str
    severity: str
    description: str


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "service": "Real-Time Intrusion Detection System",
        "status": "online",
        "mode": "rule-based",
        "components": [
            "FastAPI",
            "Network Packet Sniffer",
            "Flow Tracker",
            "Detection Engine",
            "SQLite Database"
        ]
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():

    database_status = "connected"

    try:
        connection = sqlite3.connect(DATABASE)

        connection.execute(
            "SELECT 1"
        )

        connection.close()

    except sqlite3.Error:
        database_status = "error"

    return {
        "status": "online",
        "service": "IDS API",
        "database": database_status
    }


# =========================================================
# AUTHENTICATION EVENT INGESTION
# =========================================================

@app.post("/events")
def receive_event(event: SecurityEvent):

    detection_event = {
        "timestamp": datetime.now().isoformat(),
        "ip_address": event.ip_address,
        "username": event.username,
        "status": event.status
    }

    detector.process_event(
        detection_event
    )

    return {
        "message": "Security event processed",
        "event": detection_event
    }


# =========================================================
# NETWORK IDS ALERT INGESTION
# =========================================================

@app.post("/network-events")
def receive_network_alert(alert: NetworkAlert):

    print()
    print("=" * 70)
    print("NETWORK IDS ALERT RECEIVED")
    print("=" * 70)

    print(
        f"Attack Type : {alert.alert_type}"
    )

    print(
        f"Source IP   : {alert.ip_address}"
    )

    print(
        f"Severity    : {alert.severity}"
    )

    print(
        f"Description : {alert.description}"
    )

    print("=" * 70)
    print()

    # Save alert to SQLite
    save_alert(
        alert.timestamp,
        alert.ip_address,
        alert.username,
        alert.alert_type,
        alert.severity,
        alert.description
    )

    return {
        "message": "Network intrusion alert recorded",
        "alert": {
            "timestamp": alert.timestamp,
            "ip_address": alert.ip_address,
            "username": alert.username,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "description": alert.description
        }
    }


# =========================================================
# GET ALL IDS ALERTS
# =========================================================

@app.get("/alerts")
def get_alerts():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
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
    """)

    alerts = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return {
        "count": len(alerts),
        "alerts": alerts
    }


# =========================================================
# IDS STATISTICS
# =========================================================

@app.get("/stats")
def get_stats():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # -----------------------------------------------------
    # TOTAL ALERTS
    # -----------------------------------------------------

    cursor.execute(
        "SELECT COUNT(*) FROM alerts"
    )

    total = cursor.fetchone()[0]

    # -----------------------------------------------------
    # HIGH SEVERITY
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'HIGH'
    """)

    high = cursor.fetchone()[0]

    # -----------------------------------------------------
    # MEDIUM SEVERITY
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'MEDIUM'
    """)

    medium = cursor.fetchone()[0]

    # -----------------------------------------------------
    # LOW SEVERITY
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'LOW'
    """)

    low = cursor.fetchone()[0]

    # -----------------------------------------------------
    # UNIQUE SOURCE IPS
    # -----------------------------------------------------

    cursor.execute("""
        SELECT COUNT(DISTINCT ip_address)
        FROM alerts
    """)

    unique_sources = cursor.fetchone()[0]

    # -----------------------------------------------------
    # ATTACK TYPE DISTRIBUTION
    # -----------------------------------------------------

    cursor.execute("""
        SELECT
            alert_type,
            COUNT(*)
        FROM alerts
        GROUP BY alert_type
        ORDER BY COUNT(*) DESC
    """)

    attack_types = {
        row[0]: row[1]
        for row in cursor.fetchall()
    }

    # -----------------------------------------------------
    # SEVERITY DISTRIBUTION
    # -----------------------------------------------------

    cursor.execute("""
        SELECT
            severity,
            COUNT(*)
        FROM alerts
        GROUP BY severity
    """)

    severity_distribution = {
        row[0]: row[1]
        for row in cursor.fetchall()
    }

    connection.close()

    return {
        "total_alerts": total,
        "high_severity": high,
        "medium_severity": medium,
        "low_severity": low,
        "unique_sources": unique_sources,
        "attack_types": attack_types,
        "severity_distribution": severity_distribution
    }