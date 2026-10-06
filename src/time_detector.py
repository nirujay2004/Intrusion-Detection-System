# -----------------------------------------
# Time-Based Intrusion Detection Engine
# -----------------------------------------

from log_parser import parse_logs


LOG_FILE = "data/sample_logs.txt"

THRESHOLD = 3

TIME_WINDOW = 5 * 60


# -----------------------------------------
# Get parsed security events
# -----------------------------------------

events = parse_logs(LOG_FILE)


# -----------------------------------------
# Store failed attempts by IP
# -----------------------------------------

failed_attempts = {}


for event in events:

    if event["status"] == "LOGIN_FAILED":

        ip_address = event["ip_address"]
        timestamp = event["timestamp"]

        if ip_address not in failed_attempts:

            failed_attempts[ip_address] = []

        failed_attempts[ip_address].append(timestamp)


# -----------------------------------------
# Detect brute-force activity
# -----------------------------------------

print("\n========== TIME-BASED SECURITY ANALYSIS ==========\n")


for ip_address, timestamps in failed_attempts.items():

    timestamps.sort()

    alert_triggered = False

    for i in range(len(timestamps)):

        start_time = timestamps[i]

        count = 1

        for j in range(i + 1, len(timestamps)):

            time_difference = (
                timestamps[j] - start_time
            ).total_seconds()

            if time_difference <= TIME_WINDOW:

                count += 1

            else:

                break

        if count >= THRESHOLD:

            print("🚨 SECURITY ALERT")
            print("IP Address:", ip_address)
            print("Failed Attempts:", count)
            print("Time Window: 5 minutes")
            print("Possible brute-force activity!")
            print("-" * 50)

            alert_triggered = True

            break

    if not alert_triggered:

        print("IP Address:", ip_address)
        print("Status: Normal")
        print("-" * 50)