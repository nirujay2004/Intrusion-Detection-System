# -----------------------------------------
# SQLite Database
# -----------------------------------------

import sqlite3


DATABASE = "data/security_alerts.db"


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
        timestamp,
        ip_address,
        username,
        alert_type,
        severity,
        description
    ))

    connection.commit()

    connection.close()


if __name__ == "__main__":

    create_database()

    print("Database created successfully!")