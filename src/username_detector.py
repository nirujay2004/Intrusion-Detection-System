# -----------------------------------------
# Suspicious Username Detection
# -----------------------------------------

from log_parser import parse_logs


LOG_FILE = "data/sample_logs.txt"

USERNAME_THRESHOLD = 3


# -----------------------------------------
# Read parsed events
# -----------------------------------------

events = parse_logs(LOG_FILE)


# -----------------------------------------
# Store usernames attempted by each IP
# -----------------------------------------

ip_usernames = {}


for event in events:

    if event["status"] == "LOGIN_FAILED":

        ip_address = event["ip_address"]
        username = event["username"]

        if ip_address not in ip_usernames:

            ip_usernames[ip_address] = set()

        ip_usernames[ip_address].add(username)


# -----------------------------------------
# Detect suspicious username activity
# -----------------------------------------

print("\n========== USERNAME ANALYSIS ==========\n")


for ip_address, usernames in ip_usernames.items():

    username_count = len(usernames)

    print("IP Address:", ip_address)
    print("Unique usernames attempted:", username_count)

    if username_count >= USERNAME_THRESHOLD:

        print("🚨 ALERT: Multiple usernames targeted!")
        print("Usernames:", ", ".join(usernames))
        print("Possible account enumeration activity!")

    else:

        print("Status: Normal")

    print("-" * 50)