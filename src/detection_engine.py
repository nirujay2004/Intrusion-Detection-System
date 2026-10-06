# -----------------------------------------
# Central Intrusion Detection Engine
# -----------------------------------------

from log_parser import parse_logs
from database import create_database, save_alert


LOG_FILE = "data/sample_logs.txt"

# Detection thresholds
FAILURE_THRESHOLD = 3
USERNAME_THRESHOLD = 3
TIME_WINDOW = 5 * 60


# -----------------------------------------
# Load security events
# -----------------------------------------

events = parse_logs(LOG_FILE)
create_database()

# Make sure events are in chronological order
events.sort(key=lambda event: event["timestamp"])


print("\n")
print("=" * 60)
print("        INTRUSION DETECTION SYSTEM")
print("=" * 60)


# =========================================================
# RULE 1 — BRUTE-FORCE DETECTION
# =========================================================

print("\n[ RULE 1 ] Brute-Force Detection")
print("-" * 60)


failed_attempts = {}


for event in events:

    if event["status"] == "LOGIN_FAILED":

        ip_address = event["ip_address"]
        timestamp = event["timestamp"]

        if ip_address not in failed_attempts:
            failed_attempts[ip_address] = []

        failed_attempts[ip_address].append(timestamp)


brute_force_detected = False


for ip_address, timestamps in failed_attempts.items():

    timestamps.sort()

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

        if count >= FAILURE_THRESHOLD:

            print("🚨 ALERT: Possible brute-force attack")
            print("IP Address:", ip_address)
            print("Failed Attempts:", count)
            print("Time Window: 5 minutes")
            
            save_alert(
                timestamp=start_time,
                ip_address=ip_address,
                username="Multiple/Unknown",
                alert_type="Brute Force",
                severity="HIGH",
                description=f"{count} failed login attempts within 5 minutes"
            )
            

            print("-" * 60)

            brute_force_detected = True

            break


if not brute_force_detected:

    print("✅ No brute-force activity detected.")


# =========================================================
# RULE 2 — USERNAME ENUMERATION
# =========================================================

print("\n[ RULE 2 ] Username Enumeration Detection")
print("-" * 60)


ip_usernames = {}


for event in events:

    if event["status"] == "LOGIN_FAILED":

        ip_address = event["ip_address"]
        username = event["username"]

        if ip_address not in ip_usernames:
            ip_usernames[ip_address] = set()

        ip_usernames[ip_address].add(username)


username_attack_detected = False


for ip_address, usernames in ip_usernames.items():

    username_count = len(usernames)

    if username_count >= USERNAME_THRESHOLD:

        print("🚨 ALERT: Multiple usernames targeted")
        print("IP Address:", ip_address)
        print("Unique Usernames:", username_count)
        print("Usernames:", ", ".join(usernames))
        print("Possible account enumeration activity.")
        
        save_alert(
            timestamp=events[-1]["timestamp"],
            ip_address=ip_address,
            username="Multiple",
            alert_type="Username Enumeration",
            severity="MEDIUM",
            description=f"{username_count} different usernames targeted"
        )

        print("-" * 60)

        username_attack_detected = True


if not username_attack_detected:

    print("✅ No username enumeration detected.")


# =========================================================
# RULE 3 — SUCCESS AFTER MULTIPLE FAILURES
# =========================================================

print("\n[ RULE 3 ] Successful Login After Repeated Failures")
print("-" * 60)


success_attack_detected = False


for i, event in enumerate(events):

    if event["status"] != "LOGIN_SUCCESS":
        continue

    ip_address = event["ip_address"]
    username = event["username"]

    success_time = event["timestamp"]

    failed_count = 0


    # Look at previous events
    for previous_event in reversed(events[:i]):

        # Same IP + same username + failed login
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


    if failed_count >= FAILURE_THRESHOLD:

        print("🚨 HIGH SEVERITY ALERT")
        print("IP Address:", ip_address)
        print("Username:", username)
        print("Failed Attempts Before Success:", failed_count)
        print("Time Window: 5 minutes")
        print("⚠️ Successful login after repeated failures!")

        save_alert(
            timestamp=success_time,
            ip_address=ip_address,
            username=username,
            alert_type="Successful Login After Failures",
            severity="HIGH",
            description=f"Successful login after {failed_count} failed attempts"
        )
        print("-" * 60)

        success_attack_detected = True


if not success_attack_detected:

    print("✅ No suspicious successful logins detected.")


# =========================================================
# FINAL SUMMARY
# =========================================================

print("\n")
print("=" * 60)
print("                 ANALYSIS COMPLETE")
print("=" * 60)

print("\nDetection rules executed:")
print("1. Brute-force detection")
print("2. Username enumeration detection")
print("3. Successful login after repeated failures")

print("\nStatus: Security analysis completed.")
print("=" * 60)