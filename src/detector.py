# -----------------------------------------
# Intrusion Detection Engine
# -----------------------------------------

log_file = "data/sample_logs.txt"

# Dictionary to store failed login attempts
failed_attempts = {}

# Read the log file
with open(log_file, "r") as file:

    for log in file:

        log = log.strip()

        # Split the log into different parts
        parts = log.split(",")

        timestamp = parts[0]
        ip_address = parts[1]
        username = parts[2]
        status = parts[3]

        # Check if the login failed
        if status == "LOGIN_FAILED":

            # If IP does not exist in dictionary, start at 0
            if ip_address not in failed_attempts:
                failed_attempts[ip_address] = 0

            # Increase failed login count
            failed_attempts[ip_address] += 1


# -----------------------------------------
# Detect suspicious IP addresses
# -----------------------------------------

THRESHOLD = 3

print("\n========== SECURITY ANALYSIS ==========\n")

for ip_address, count in failed_attempts.items():

    print("IP Address:", ip_address)
    print("Failed Attempts:", count)

    if count >= THRESHOLD:

        print("🚨 ALERT: Possible brute-force activity!")

    else:

        print("Status: Normal")

    print("-" * 40)