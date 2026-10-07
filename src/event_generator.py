import os
from datetime import datetime

import requests


API_URL = (
    os.getenv("IDS_API_URL")
    or "http://127.0.0.1:8000"
).rstrip("/") + "/network-events"


def send_event(
    ip_address,
    alert_type,
    severity,
    description
):
    payload = {
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip_address,
        "username": "N/A",
        "alert_type": alert_type,
        "severity": severity,
        "description": description
    }

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=5
        )

        print(
            f"[EVENT] {alert_type} | "
            f"Source: {ip_address} | "
            f"Status: {response.status_code}"
        )

        if response.status_code != 200:
            print("Response:", response.text)

    except requests.exceptions.RequestException as error:
        print("Could not connect to FastAPI:", error)


def port_scan():
    print("\nStarting Port Scan simulation...")

    send_event(
        "10.10.10.50",
        "Port Scan",
        "HIGH",
        "15 destination ports contacted within 4.2 seconds"
    )


def syn_flood():
    print("\nStarting SYN Flood simulation...")

    send_event(
        "10.10.10.60",
        "SYN Flood",
        "HIGH",
        "100 SYN packets detected within 3.0 seconds"
    )


def icmp_flood():
    print("\nStarting ICMP Flood simulation...")

    send_event(
        "10.10.10.70",
        "ICMP Flood",
        "HIGH",
        "100 ICMP packets detected within 3.0 seconds"
    )


def normal_traffic():
    print("\nGenerating normal traffic...")

    send_event(
        "192.168.1.20",
        "Normal Traffic",
        "LOW",
        "Normal network activity detected"
    )


def main():
    print("=" * 60)
    print("REAL-TIME IDS EVENT GENERATOR")
    print("=" * 60)

    while True:
        print("\nChoose an event to simulate:")
        print("1. Port Scan")
        print("2. SYN Flood")
        print("3. ICMP Flood")
        print("4. Normal Traffic")
        print("5. Run all attacks")
        print("0. Exit")

        choice = input("\nEnter choice: ").strip()

        if choice == "1":
            port_scan()

        elif choice == "2":
            syn_flood()

        elif choice == "3":
            icmp_flood()

        elif choice == "4":
            normal_traffic()

        elif choice == "5":
            port_scan()
            syn_flood()
            icmp_flood()

        elif choice == "0":
            print("Exiting event generator.")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()