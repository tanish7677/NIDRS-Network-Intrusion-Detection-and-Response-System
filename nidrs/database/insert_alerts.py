import sqlite3
conn = sqlite3.connect("alerts.db")
cursor = conn.cursor()
alerts = [
    ("DoS", "High"),
    ("Probe", "Medium"),
    ("R2L", "Low"),
    ("U2R", "Critical")
]
cursor.executemany(
    """
    INSERT INTO alerts(
        attack_type,
        severity
    )
    VALUES(?,?)
    """,
    alerts
)
conn.commit()
print("All Alerts Inserted Successfully")
conn.close()