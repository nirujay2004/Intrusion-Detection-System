from datetime import datetime


class NetworkDetector:

    def __init__(self):
        # Prevent the same source from generating
        # the same alert repeatedly.
        self.alerted_sources = set()

    def detect(self, flow):

        alerts = []

        source_ip = flow["source_ip"]

        packet_count = flow["packet_count"]
        syn_count = flow["syn_count"]
        unique_ports = flow["unique_destination_ports"]
        duration = flow["duration"]
        protocol = flow["protocol"]

        # Avoid division-by-zero / invalid duration
        if duration <= 0:
            duration = 0.001

        # =====================================================
        # 1. PORT SCAN DETECTION
        # =====================================================

        if unique_ports >= 10 and duration <= 10:

            alert_key = (
                source_ip,
                "Port Scan"
            )

            if alert_key not in self.alerted_sources:

                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "ip_address": source_ip,
                    "username": "N/A",
                    "alert_type": "Port Scan",
                    "severity": "HIGH",
                    "description": (
                        f"{unique_ports} destination ports "
                        f"contacted within {duration:.1f} seconds"
                    )
                }

                alerts.append(alert)

                self.alerted_sources.add(alert_key)

        # =====================================================
        # 2. SYN FLOOD DETECTION
        # =====================================================

        if syn_count >= 50 and duration <= 5:

            alert_key = (
                source_ip,
                "SYN Flood"
            )

            if alert_key not in self.alerted_sources:

                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "ip_address": source_ip,
                    "username": "N/A",
                    "alert_type": "SYN Flood",
                    "severity": "HIGH",
                    "description": (
                        f"{syn_count} SYN packets "
                        f"detected within {duration:.1f} seconds"
                    )
                }

                alerts.append(alert)

                self.alerted_sources.add(alert_key)

        # =====================================================
        # 3. ICMP FLOOD DETECTION
        # =====================================================

        if (
            protocol == "ICMP"
            and packet_count >= 50
            and duration <= 5
        ):

            alert_key = (
                source_ip,
                "ICMP Flood"
            )

            if alert_key not in self.alerted_sources:

                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "ip_address": source_ip,
                    "username": "N/A",
                    "alert_type": "ICMP Flood",
                    "severity": "HIGH",
                    "description": (
                        f"{packet_count} ICMP packets "
                        f"detected within {duration:.1f} seconds"
                    )
                }

                alerts.append(alert)

                self.alerted_sources.add(alert_key)

        # =====================================================
        # RETURN DETECTIONS
        # =====================================================

        return alerts