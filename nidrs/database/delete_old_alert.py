import sqlite3

conn = sqlite3.connect("alerts.db")
cursor = conn.cursor()

cursor.execute("""
DELETE FROM alerts
WHERE attack_type = 'Live Anomaly'
AND detected_at IS NULL
""")

print("Deleted:", cursor.rowcount)

conn.commit()
conn.close()

print("Database Cleanup Completed")