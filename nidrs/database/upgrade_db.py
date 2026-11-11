import sqlite3

conn = sqlite3.connect("alerts.db")
cursor = conn.cursor()

new_columns = [
    ("src_ip", "TEXT"),
    ("dst_ip", "TEXT"),
    ("src_port", "INTEGER"),
    ("dst_port", "INTEGER"),
    ("protocol", "TEXT"),
    ("packet_count", "INTEGER"),
    ("total_bytes", "INTEGER"),
    ("duration", "REAL"),
    ("packets_per_second", "REAL"),
    ("bytes_per_second", "REAL"),
    ("average_packet_size", "REAL")
]

cursor.execute("PRAGMA table_info(alerts)")

existing_columns = [
    column[1]
    for column in cursor.fetchall()
]

for column_name, column_type in new_columns:

    if column_name not in existing_columns:

        cursor.execute(
            f"""
            ALTER TABLE alerts
            ADD COLUMN {column_name} {column_type}
            """
        )

        print(
            f"Added Column: {column_name}"
        )

    else:

        print(
            f"Column Already Exists: {column_name}"
        )

conn.commit()
conn.close()

print("\nDatabase Upgrade Completed")