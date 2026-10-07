import os
import requests

from scapy.all import sniff, IP, TCP, UDP, ICMP

from flow_tracker import FlowTracker
from network_detector import NetworkDetector


# =========================================================
# CONFIGURATION
# =========================================================

# API_URL = "http://127.0.0.1:8000/network-events"
API_URL = os.getenv(
    "IDS_API_URL",
    "http://127.0.0.1:8000/network-events"
)
API_TIMEOUT = 3


# =========================================================
# IDS COMPONENTS
# =========================================================

flow_tracker = FlowTracker()

detector = NetworkDetector()


# =========================================================
# SEND ALERT TO FASTAPI
# =========================================================

def send_alert_to_api(alert):

    try:

        response = requests.post(
            API_URL,
            json=alert,
            timeout=API_TIMEOUT
        )

        if response.status_code == 200:

            print("✓ Alert sent to FastAPI.")

        else:

            print(
                f"⚠ FastAPI returned HTTP "
                f"{response.status_code}"
            )

    except requests.exceptions.ConnectionError:

        print(
            "⚠ FastAPI is unavailable. "
            "Alert detected locally but was not sent."
        )

    except requests.exceptions.Timeout:

        print(
            "⚠ FastAPI request timed out."
        )

    except requests.exceptions.RequestException as error:

        print(
            f"⚠ API communication error: {error}"
        )


# =========================================================
# PROCESS NETWORK PACKET
# =========================================================

def process_packet(packet):

    # -----------------------------------------------------
    # Ignore packets without an IP layer
    # -----------------------------------------------------

    if IP not in packet:

        return

    ip = packet[IP]

    source_ip = ip.src

    destination_ip = ip.dst

    packet_size = len(packet)

    source_port = None

    destination_port = None

    tcp_flags = None

    protocol = "OTHER"


    # =====================================================
    # TCP PACKET
    # =====================================================

    if TCP in packet:

        protocol = "TCP"

        source_port = packet[TCP].sport

        destination_port = packet[TCP].dport

        tcp_flags = str(packet[TCP].flags)


    # =====================================================
    # UDP PACKET
    # =====================================================

    elif UDP in packet:

        protocol = "UDP"

        source_port = packet[UDP].sport

        destination_port = packet[UDP].dport


    # =====================================================
    # ICMP PACKET
    # =====================================================

    elif ICMP in packet:

        protocol = "ICMP"


    # =====================================================
    # UPDATE NETWORK FLOW
    # =====================================================

    flow = flow_tracker.update_flow(

        source_ip=source_ip,

        destination_ip=destination_ip,

        source_port=source_port,

        destination_port=destination_port,

        protocol=protocol,

        packet_size=packet_size,

        tcp_flags=tcp_flags
    )


    # =====================================================
    # RUN IDS DETECTION RULES
    # =====================================================

    alerts = detector.detect(flow)


    # =====================================================
    # PROCESS DETECTED ALERTS
    # =====================================================

    for alert in alerts:

        print()

        print("=" * 70)

        print("🚨 NETWORK INTRUSION DETECTED")

        print("=" * 70)

        print(
            f"Timestamp : {alert['timestamp']}"
        )

        print(
            f"Source IP : {alert['ip_address']}"
        )

        print(
            f"Attack    : {alert['alert_type']}"
        )

        print(
            f"Severity  : {alert['severity']}"
        )

        print(
            f"Details   : {alert['description']}"
        )

        print("=" * 70)

        print()


        # -------------------------------------------------
        # Send detected threat to FastAPI
        # -------------------------------------------------

        send_alert_to_api(alert)


# =========================================================
# START NETWORK IDS
# =========================================================

def start_sniffer():

    print()

    print("=" * 70)

    print("REAL-TIME NETWORK INTRUSION DETECTION SYSTEM")

    print("=" * 70)

    print()

    print("Packet capture : ACTIVE")

    print("Flow tracking  : ACTIVE")

    print("Detection      : ACTIVE")

    print("Mode           : RULE-BASED")

    print(
        f"FastAPI        : {API_URL}"
    )

    print()

    print("Monitoring network traffic...")

    print("Press CTRL+C to stop.")

    print()

    print("-" * 70)

    try:

        sniff(
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print()

        print("=" * 70)

        print("NETWORK IDS STOPPED")

        print("=" * 70)


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    start_sniffer()