from scapy.all import sniff, IP, TCP, UDP, ICMP


def process_packet(packet):

    if IP not in packet:
        return

    ip = packet[IP]

    source_ip = ip.src
    destination_ip = ip.dst
    protocol = ip.proto
    packet_size = len(packet)

    source_port = None
    destination_port = None
    flags = None

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        flags = str(packet[TCP].flags)

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    print(
        f"[PACKET] "
        f"{source_ip}:{source_port} -> "
        f"{destination_ip}:{destination_port} | "
        f"Protocol={protocol} | "
        f"Size={packet_size} | "
        f"Flags={flags}"
    )


def start_sniffer():

    print("=" * 70)
    print("REAL-TIME NETWORK PACKET SNIFFER")
    print("=" * 70)
    print("Monitoring network traffic...")
    print("Press CTRL+C to stop.")
    print()

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_sniffer()