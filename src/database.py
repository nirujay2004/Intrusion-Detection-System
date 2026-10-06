# -----------------------------------------
# SQLite Database
# -----------------------------------------

import sqlite3


DATABASE = "data/security_alerts.db"


# -----------------------------------------
# Create Database
# -----------------------------------------

def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            ip_address TEXT,

            username TEXT,

            alert_type TEXT,

            severity TEXT,

            description TEXT
        )
    """)

    connection.commit()

    connection.close()


# -----------------------------------------
# Save Security Alert
# -----------------------------------------

def save_alert(
    timestamp,
    ip_address,
    username,
    alert_type,
    severity,
    description
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # Check whether this alert already exists
    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE timestamp = ?
        AND ip_address = ?
        AND username = ?
        AND alert_type = ?
        AND severity = ?
        AND description = ?
    """, (
        str(timestamp),
        ip_address,
        username,
        alert_type,
        severity,
        description
    ))

    existing_alert = cursor.fetchone()


    # -----------------------------------------
    # Insert only if alert does not exist
    # -----------------------------------------

    if existing_alert is None:

        cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                ip_address,
                username,
                alert_type,
                severity,
                description
            )

            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(timestamp),
            ip_address,
            username,
            alert_type,
            severity,
            description
        ))

        connection.commit()

        print("Alert saved to database.")


    else:

        print("Duplicate alert ignored.")


    connection.close()


# -----------------------------------------
# Test Database Creation
# -----------------------------------------

if __name__ == "__main__":

    create_database()

    print("Database created successfully!")