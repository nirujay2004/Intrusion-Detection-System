from collections import defaultdict
from datetime import datetime


class FlowTracker:

    def __init__(self):
        self.flows = defaultdict(
            lambda: {
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": None,
                "last_seen": None,
                "syn_count": 0,
                "destination_ports": set()
            }
        )

    def update_flow(
        self,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol,
        packet_size,
        tcp_flags=None
    ):

        flow_key = (
            source_ip,
            destination_ip,
            protocol
        )

        now = datetime.now()

        flow = self.flows[flow_key]

        # First packet
        if flow["first_seen"] is None:
            flow["first_seen"] = now

        flow["last_seen"] = now

        # Packet statistics
        flow["packet_count"] += 1
        flow["byte_count"] += packet_size

        # Track destination ports
        if destination_port is not None:
            flow["destination_ports"].add(destination_port)

        # Track SYN packets
        if tcp_flags is not None:

            if "S" in tcp_flags and "A" not in tcp_flags:
                flow["syn_count"] += 1

        duration = (
            flow["last_seen"] -
            flow["first_seen"]
        ).total_seconds()

        return {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,

            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],

            "duration": duration,

            "syn_count": flow["syn_count"],

            "unique_destination_ports":
                len(flow["destination_ports"])
        }