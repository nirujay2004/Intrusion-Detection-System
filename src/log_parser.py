# -----------------------------------------
# Security Log Parser
# -----------------------------------------

from datetime import datetime


def parse_logs(log_file):
    """
    Read the security log file and convert
    each line into a structured dictionary.
    """

    events = []

    with open(log_file, "r") as file:

        for log in file:

            log = log.strip()

            if not log:
                continue

            parts = log.split(",")

            timestamp = datetime.strptime(
                parts[0],
                "%Y-%m-%d %H:%M:%S"
            )

            ip_address = parts[1]
            username = parts[2]
            status = parts[3]

            event = {
                "timestamp": timestamp,
                "ip_address": ip_address,
                "username": username,
                "status": status
            }

            events.append(event)

    return events


# -----------------------------------------
# Test the parser
# -----------------------------------------

if __name__ == "__main__":

    logs = parse_logs("data/sample_logs.txt")

    print("Total events:", len(logs))

    for event in logs:

        print(event)