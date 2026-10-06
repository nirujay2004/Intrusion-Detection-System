# -----------------------------------------
# Real-Time IDS Detection Engine
# -----------------------------------------

from collections import defaultdict, deque
from datetime import timedelta

from src.database import save_alert


TIME_WINDOW = timedelta(minutes=5)

BRUTE_FORCE_THRESHOLD = 3
USERNAME_ENUMERATION_THRESHOLD = 3


class DetectionEngine:

    def __init__(self):

        # Failed login timestamps
        self.failed_attempts = defaultdict(deque)

        # Username activity per IP
        self.username_activity = defaultdict(deque)

        # Track whether an alert has already
        # been generated for the current attack
        self.brute_force_alerted = set()

        self.enumeration_alerted = set()

        self.success_alerted = set()


    # -----------------------------------------
    # Process One Event
    # -----------------------------------------

    def process_event(self, event):

        timestamp = event["timestamp"]
        ip_address = event["ip_address"]
        username = event["username"]
        status = event["status"]

        print(
            f"[EVENT] {timestamp} | "
            f"{ip_address} | "
            f"{username} | "
            f"{status}"
        )

        if status == "LOGIN_FAILED":

            self.handle_failed_login(
                timestamp,
                ip_address,
                username
            )

        elif status == "LOGIN_SUCCESS":

            self.handle_successful_login(
                timestamp,
                ip_address,
                username
            )


    # -----------------------------------------
    # Failed Login
    # -----------------------------------------

    def handle_failed_login(
        self,
        timestamp,
        ip_address,
        username
    ):

        key = (
            ip_address,
            username
        )

        self.failed_attempts[key].append(
            timestamp
        )

        self.username_activity[
            ip_address
        ].append(
            (timestamp, username)
        )

        self.cleanup_old_events(
            timestamp,
            ip_address,
            username
        )

        # -----------------------------------------
        # RULE 1
        # Brute Force
        # -----------------------------------------

        failures = len(
            self.failed_attempts[key]
        )

        if (
            failures >= BRUTE_FORCE_THRESHOLD
            and key not in self.brute_force_alerted
        ):

            self.brute_force_alerted.add(key)

            print()
            print("=" * 50)
            print("🚨 BRUTE FORCE ATTACK DETECTED")
            print("=" * 50)

            print(
                f"IP Address : {ip_address}"
            )

            print(
                f"Username   : {username}"
            )

            print(
                f"Attempts   : {failures}"
            )

            print()

            save_alert(
                timestamp,
                ip_address,
                username,
                "Brute Force",
                "HIGH",
                f"{failures} failed login attempts within 5 minutes"
            )

        # -----------------------------------------
        # RULE 2
        # Username Enumeration
        # -----------------------------------------

        activities = self.username_activity[
            ip_address
        ]

        unique_usernames = set(
            user
            for _, user in activities
        )

        if (
            len(unique_usernames)
            >= USERNAME_ENUMERATION_THRESHOLD
            and ip_address
            not in self.enumeration_alerted
        ):

            self.enumeration_alerted.add(
                ip_address
            )

            print()
            print("=" * 50)
            print("🚨 USERNAME ENUMERATION DETECTED")
            print("=" * 50)

            print(
                f"IP Address : {ip_address}"
            )

            print(
                f"Usernames  : {len(unique_usernames)}"
            )

            print()

            save_alert(
                timestamp,
                ip_address,
                "Multiple",
                "Username Enumeration",
                "MEDIUM",
                f"{len(unique_usernames)} different usernames targeted"
            )


    # -----------------------------------------
    # Successful Login
    # -----------------------------------------

    def handle_successful_login(
        self,
        timestamp,
        ip_address,
        username
    ):

        key = (
            ip_address,
            username
        )

        self.cleanup_old_events(
            timestamp,
            ip_address,
            username
        )

        failures = len(
            self.failed_attempts[key]
        )

        # -----------------------------------------
        # RULE 3
        # Successful Login After Failures
        # -----------------------------------------

        if (
            failures >= BRUTE_FORCE_THRESHOLD
            and key not in self.success_alerted
        ):

            self.success_alerted.add(key)

            print()
            print("=" * 50)
            print("🚨 SUSPICIOUS SUCCESSFUL LOGIN")
            print("=" * 50)

            print(
                f"IP Address : {ip_address}"
            )

            print(
                f"Username   : {username}"
            )

            print(
                f"Previous failures : {failures}"
            )

            print()

            save_alert(
                timestamp,
                ip_address,
                username,
                "Successful Login After Failures",
                "HIGH",
                f"Successful login after {failures} failed attempts"
            )


    # -----------------------------------------
    # Remove Old Events
    # -----------------------------------------

    def cleanup_old_events(
        self,
        timestamp,
        ip_address,
        username
    ):

        cutoff = (
            timestamp - TIME_WINDOW
        )

        key = (
            ip_address,
            username
        )

        while (
            self.failed_attempts[key]
            and
            self.failed_attempts[key][0]
            < cutoff
        ):

            self.failed_attempts[key].popleft()

            # Allow a future attack episode
            # to generate a new alert.
            self.brute_force_alerted.discard(
                key
            )

            self.success_alerted.discard(
                key
            )


        activity = self.username_activity[
            ip_address
        ]

        while (
            activity
            and
            activity[0][0]
            < cutoff
        ):

            activity.popleft()

            # If no usernames remain in the
            # current window, reset enumeration.
            if not activity:

                self.enumeration_alerted.discard(
                    ip_address
                )