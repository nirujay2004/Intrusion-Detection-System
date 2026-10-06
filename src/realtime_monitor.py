# -----------------------------------------
# Real-Time Intrusion Detection Monitor
# -----------------------------------------

import time
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta

from log_parser import parse_line
from database import create_database, save_alert


LOG_FILE = "data/sample_logs.txt"

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5
USERNAME_ENUMERATION_THRESHOLD = 3


# Store recent events
failed_attempts = defaultdict(deque)
usernames_by_ip = defaultdict(set)


def process_event(event):
    """
    Process one newly received log event.
    """

    timestamp = event["timestamp"]
    ip_address = event["ip_address"]
    username = event["username"]
    status = event["status"]

    print(
        f"[NEW EVENT] {timestamp} | "
        f"{ip_address} | {username} | {status}"
    )

    # -----------------------------------------
    # LOGIN FAILED
    # -----------------------------------------

    if status == "LOGIN_FAILED":

        failed_attempts[(ip_address, username)].append(timestamp)

        usernames_by_ip[ip_address].add(username)

        # Remove failures older than 5 minutes
        cutoff = timestamp - timedelta(minutes=TIME_WINDOW_MINUTES)

        while (
            failed_attempts[(ip_address, username)]
            and failed_attempts[(ip_address, username)][0] < cutoff
        ):
            failed_attempts[(ip_address, username)].popleft()

        # -----------------------------------------
        # Rule 1: Brute Force
        # -----------------------------------------

        attempts = len(
            failed_attempts[(ip_address, username)]
        )

        if attempts == BRUTE_FORCE_THRESHOLD:

            description = (
                f"{attempts} failed login attempts "
                f"within {TIME_WINDOW_MINUTES} minutes"
            )

            print("\n🚨 BRUTE FORCE DETECTED!")
            print(f"IP: {ip_address}")
            print(f"Username: {username}")
            print(f"Attempts: {attempts}\n")

            save_alert(
                timestamp,
                ip_address,
                username,
                "Brute Force",
                "HIGH",
                description
            )

        # -----------------------------------------
        # Rule 2: Username Enumeration
        # -----------------------------------------

        unique_usernames = len(
            usernames_by_ip[ip_address]
        )

        if unique_usernames == USERNAME_ENUMERATION_THRESHOLD:

            description = (
                f"{unique_usernames} different usernames targeted"
            )

            print("\n🚨 USERNAME ENUMERATION DETECTED!")
            print(f"IP: {ip_address}")
            print(f"Usernames: {unique_usernames}\n")

            save_alert(
                timestamp,
                ip_address,
                "Multiple",
                "Username Enumeration",
                "MEDIUM",
                description
            )

    # -----------------------------------------
    # LOGIN SUCCESS
    # -----------------------------------------

    elif status == "LOGIN_SUCCESS":

        key = (ip_address, username)

        recent_failures = failed_attempts[key]

        cutoff = timestamp - timedelta(minutes=TIME_WINDOW_MINUTES)

        recent_failures = [
            failure
            for failure in recent_failures
            if failure >= cutoff
        ]

        # -----------------------------------------
        # Rule 3: Successful Login After Failures
        # -----------------------------------------

        if len(recent_failures) >= BRUTE_FORCE_THRESHOLD:

            description = (
                f"Successful login after "
                f"{len(recent_failures)} failed attempts"
            )

            print("\n🚨 SUSPICIOUS SUCCESSFUL LOGIN!")
            print(f"IP: {ip_address}")
            print(f"Username: {username}")
            print(f"Previous failures: {len(recent_failures)}\n")

            save_alert(
                timestamp,
                ip_address,
                username,
                "Successful Login After Failures",
                "HIGH",
                description
            )


def monitor_log_file():

    print("=========================================")
    print(" REAL-TIME INTRUSION DETECTION SYSTEM")
    print("=========================================")
    print()
    print(f"Monitoring: {LOG_FILE}")
    print("Waiting for new log events...")
    print("Press Ctrl+C to stop.")
    print()

    create_database()

    # Remember where we have already read
    # file_position = 0
    file_position = os.path.getsize(LOG_FILE)

    while True:

        try:

            # Open only briefly so other programs
            # can continue writing to the file.
            with open(LOG_FILE, "r") as log_file:

                log_file.seek(file_position)

                while True:

                    line = log_file.readline()

                    if not line:
                        break

                    line = line.strip()

                    if not line:
                        continue

                    try:

                        event = parse_line(line)

                        process_event(event)

                    except Exception as error:

                        print(
                            f"Error processing log: {error}"
                        )

                # Remember where we stopped reading
                file_position = log_file.tell()

        except FileNotFoundError:

            print(f"Log file not found: {LOG_FILE}")

        except Exception as error:

            print(f"Monitor error: {error}")

        # Check for new events every second
        time.sleep(1)
        
if __name__ == "__main__":
    monitor_log_file()