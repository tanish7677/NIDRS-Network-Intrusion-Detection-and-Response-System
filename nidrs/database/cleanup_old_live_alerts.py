import sqlite3

DB_PATH = "alerts.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("\n" + "=" * 40)
print("NIDRS DATABASE CLEANUP")
print("=" * 40)

cursor.execute("""
SELECT id, attack_type, severity, src_ip
FROM alerts
WHERE attack_type = 'Live Anomaly'
AND src_ip IS NULL
""")

old_alerts = cursor.fetchall()

print(f"\nIncomplete Live Alerts Found: {len(old_alerts)}")

if old_alerts:
    print("\nAlerts To Delete:")

    for alert in old_alerts:
        print(alert)

    cursor.execute("""
    DELETE FROM alerts
    WHERE attack_type = 'Live Anomaly'
    AND src_ip IS NULL
    """)

    deleted_count = cursor.rowcount

    conn.commit()

    print(f"\nDeleted Alerts: {deleted_count}")

else:
    print("\nNo incomplete alerts found.")

cursor.execute("""
SELECT COUNT(*)
FROM alerts
WHERE attack_type = 'Live Anomaly'
""")

remaining_live_alerts = cursor.fetchone()[0]

print(f"\nRemaining Live Alerts: {remaining_live_alerts}")

conn.close()

print("\nDatabase Cleanup Completed")
print("=" * 40)