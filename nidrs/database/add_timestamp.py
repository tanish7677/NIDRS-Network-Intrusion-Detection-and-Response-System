import sqlite3

DB_PATH = "alerts.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("\n" + "=" * 40)
print("NIDRS TIMESTAMP DATABASE UPGRADE")
print("=" * 40)

cursor.execute("PRAGMA table_info(alerts)")

columns = [
    column[1]
    for column in cursor.fetchall()
]

if "detected_at" not in columns:

    cursor.execute("""
    ALTER TABLE alerts
    ADD COLUMN detected_at TEXT
    """)

    conn.commit()

    print("Added Column: detected_at")

else:

    print("Column detected_at already exists")

conn.close()

print("\nDatabase Upgrade Completed")
print("=" * 40)