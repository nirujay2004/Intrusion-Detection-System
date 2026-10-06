# -----------------------------------------
# Successful Login After Multiple Failures
# -----------------------------------------

from log_parser import parse_logs


LOG_FILE = "data/sample_logs.txt"

FAILURE_THRESHOLD = 3

TIME_WINDOW = 5 * 60


# -----------------------------------------
# Read security events
# -----------------------------------------

events = parse_logs(LOG_FILE)


# -----------------------------------------
# Sort events by timestamp
# -----------------------------------------

events.sort(key=lambda event: event["timestamp"])


# -----------------------------------------
# Analyse login activity
# -----------------------------------------

print("\n========== SUCCESS-AFTER-FAILURE ANALYSIS ==========\n")


for i, event in enumerate(events):

    # We are only interested in successful logins
    if event["status"] != "LOGIN_SUCCESS":
        continue

    ip_address = event["ip_address"]
    username = event["username"]
    success_time = event["timestamp"]

    failed_count = 0

    # Look backwards through previous events
    for previous_event in reversed(events[:i]):

        # Only consider same IP and same username
        if (
            previous_event["ip_address"] == ip_address
            and previous_event["username"] == username
            and previous_event["status"] == "LOGIN_FAILED"
        ):

            time_difference = (
                success_time - previous_event["timestamp"]
            ).total_seconds()

            if time_difference <= TIME_WINDOW:

                failed_count += 1

            else:

                break

    # -----------------------------------------
    # Generate alert
    # -----------------------------------------

    if failed_count >= FAILURE_THRESHOLD:

        print("🚨 HIGH SEVERITY ALERT")
        print("IP Address:", ip_address)
        print("Username:", username)
        print("Failed Attempts Before Success:", failed_count)
        print("Time Window: 5 minutes")
        print("⚠️ Successful login after repeated failures!")
        print("-" * 60)