from datetime import datetime
from pathlib import Path
import sqlite3

from fastapi import FastAPI
from pydantic import BaseModel

from src.detection_engine import DetectionEngine


app = FastAPI(
    title="Real-Time IDS API",
    description="Security Event Ingestion and Intrusion Detection API",
    version="1.0.0"
)


# -----------------------------------------
# Database
# -----------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATABASE = PROJECT_ROOT / "data" / "security_alerts.db"


# -----------------------------------------
# Detection Engine
# -----------------------------------------

detector = DetectionEngine()


# -----------------------------------------
# Event Schema
# -----------------------------------------

class SecurityEvent(BaseModel):

    ip_address: str
    username: str
    status: str


# -----------------------------------------
# Root Endpoint
# -----------------------------------------

@app.get("/")
def root():

    return {
        "service": "Real-Time Intrusion Detection System",
        "status": "online"
    }


# -----------------------------------------
# Health Check
# -----------------------------------------

@app.get("/health")
def health():

    return {
        "status": "online",
        "service": "IDS API"
    }


# -----------------------------------------
# Submit Security Event
# -----------------------------------------

@app.post("/events")
def receive_event(event: SecurityEvent):

    detection_event = {
        "timestamp": datetime.now(),
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


# -----------------------------------------
# Get Alerts
# -----------------------------------------

@app.get("/alerts")
def get_alerts():

    connection = sqlite3.connect(
        DATABASE
    )

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


# -----------------------------------------
# Statistics
# -----------------------------------------

@app.get("/stats")
def get_stats():

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM alerts"
    )

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'HIGH'
    """)

    high = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'MEDIUM'
    """)

    medium = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(DISTINCT ip_address)
        FROM alerts
    """)

    unique_sources = cursor.fetchone()[0]

    connection.close()

    return {
        "total_alerts": total,
        "high_severity": high,
        "medium_severity": medium,
        "unique_sources": unique_sources
    }