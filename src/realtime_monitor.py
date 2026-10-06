# -----------------------------------------
# Real-Time IDS Log Monitor
# -----------------------------------------

import os
import time

from database import create_database
from detection_engine import DetectionEngine
from log_parser import parse_line


LOG_FILE = "data/sample_logs.txt"


def monitor_log_file():

    print()
    print("=" * 60)
    print("        REAL-TIME INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    print()

    print(
        f"📡 Monitoring: {LOG_FILE}"
    )

    print()

    print(
        "Waiting for authentication events..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    # Make sure database exists
    create_database()

    # Create detection engine
    detector = DetectionEngine()

    # Start reading from the current end
    # so old logs are not processed again.
    file_position = os.path.getsize(
        LOG_FILE
    )

    while True:

        try:

            with open(
                LOG_FILE,
                "r"
            ) as log_file:

                log_file.seek(
                    file_position
                )

                while True:

                    line = log_file.readline()

                    if not line:
                        break

                    file_position = (
                        log_file.tell()
                    )

                    try:

                        event = parse_line(
                            line
                        )

                        if event:

                            detector.process_event(
                                event
                            )

                    except Exception as error:

                        print(
                            f"⚠️ Invalid log event: {error}"
                        )

        except FileNotFoundError:

            print(
                "❌ Log file does not exist."
            )

        except Exception as error:

            print(
                f"⚠️ Monitor error: {error}"
            )

        # Check for new events every second
        time.sleep(1)


if __name__ == "__main__":

    monitor_log_file()