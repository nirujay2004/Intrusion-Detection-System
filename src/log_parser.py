# -----------------------------------------
# Security Log Parser
# -----------------------------------------

from datetime import datetime


def parse_line(log_line):
    """
    Convert one authentication log line
    into a structured event.
    """

    log_line = log_line.strip()

    if not log_line:
        return None

    parts = log_line.split(",")

    if len(parts) != 4:

        raise ValueError(
            "Invalid log format"
        )

    timestamp = datetime.strptime(
        parts[0],
        "%Y-%m-%d %H:%M:%S"
    )

    return {
        "timestamp": timestamp,
        "ip_address": parts[1],
        "username": parts[2],
        "status": parts[3]
    }