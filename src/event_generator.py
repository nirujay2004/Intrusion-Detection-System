# -----------------------------------------
# Authentication Event Simulator
# -----------------------------------------

import time
from datetime import datetime

LOG_FILE = "data/sample_logs.txt"


def write_event(
    ip_address,
    username,
    status
):

    timestamp = datetime.now().replace(
        microsecond=0
    )

    log_line = (
        f"{timestamp},"
        f"{ip_address},"
        f"{username},"
        f"{status}\n"
    )

    with open(
        LOG_FILE,
        "a"
    ) as file:

        file.write(
            log_line
        )

    print(
        f"EVENT → "
        f"{ip_address} | "
        f"{username} | "
        f"{status}"
    )


# -----------------------------------------
# Scenario 1
# Brute Force
# -----------------------------------------

def brute_force():

    ip = "10.10.10.50"
    username = "admin"

    print()
    print("===================================")
    print("SIMULATING BRUTE FORCE")
    print("===================================")

    for i in range(3):

        write_event(
            ip,
            username,
            "LOGIN_FAILED"
        )

        time.sleep(2)


# -----------------------------------------
# Scenario 2
# Username Enumeration
# -----------------------------------------

def username_enumeration():

    ip = "10.10.10.60"

    usernames = [
        "admin",
        "john",
        "manager"
    ]

    print()
    print("===================================")
    print("SIMULATING USERNAME ENUMERATION")
    print("===================================")

    for username in usernames:

        write_event(
            ip,
            username,
            "LOGIN_FAILED"
        )

        time.sleep(2)


# -----------------------------------------
# Scenario 3
# Successful Login After Failures
# -----------------------------------------

def suspicious_login():

    ip = "10.10.10.70"
    username = "admin"

    print()
    print("===================================")
    print("SIMULATING SUSPICIOUS LOGIN")
    print("===================================")

    for i in range(3):

        write_event(
            ip,
            username,
            "LOGIN_FAILED"
        )

        time.sleep(2)

    write_event(
        ip,
        username,
        "LOGIN_SUCCESS"
    )


# -----------------------------------------
# Normal Login
# -----------------------------------------

def normal_login():

    ip = "10.10.10.20"

    print()
    print("===================================")
    print("SIMULATING NORMAL LOGIN")
    print("===================================")

    write_event(
        ip,
        "employee",
        "LOGIN_SUCCESS"
    )


# -----------------------------------------
# Main Demo
# -----------------------------------------

def main():

    print()
    print("=" * 55)
    print("       AUTHENTICATION EVENT SIMULATOR")
    print("=" * 55)

    print()
    print("Choose a scenario:")
    print()
    print("1. Normal Login")
    print("2. Brute Force Attack")
    print("3. Username Enumeration")
    print("4. Successful Login After Failures")
    print("5. Run Complete Demo")
    print()

    choice = input(
        "Enter choice: "
    ).strip()

    if choice == "1":

        normal_login()

    elif choice == "2":

        brute_force()

    elif choice == "3":

        username_enumeration()

    elif choice == "4":

        suspicious_login()

    elif choice == "5":

        normal_login()

        time.sleep(2)

        brute_force()

        time.sleep(3)

        username_enumeration()

        time.sleep(3)

        suspicious_login()

    else:

        print(
            "Invalid choice."
        )


if __name__ == "__main__":

    main()