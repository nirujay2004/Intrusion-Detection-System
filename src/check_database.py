import sqlite3


DATABASE = "data/security_alerts.db"


connection = sqlite3.connect(DATABASE)

cursor = connection.cursor()


cursor.execute("""
    SELECT
        id,
        timestamp,
        ip_address,
        username,
        alert_type,
        severity,
        description
    FROM alerts
""")


alerts = cursor.fetchall()


print("\n========== STORED SECURITY ALERTS ==========\n")


for alert in alerts:

    print("ID:", alert[0])
    print("Timestamp:", alert[1])
    print("IP Address:", alert[2])
    print("Username:", alert[3])
    print("Alert Type:", alert[4])
    print("Severity:", alert[5])
    print("Description:", alert[6])

    print("-" * 60)


connection.close()