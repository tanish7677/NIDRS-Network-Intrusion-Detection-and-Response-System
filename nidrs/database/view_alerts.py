import sqlite3
conn = sqlite3.connect("alerts.db")
cursor = conn.cursor()
cursor.execute(
"""
SELECT * FROM alerts
"""
)
rows = cursor.fetchall()
for row in rows:
    print(row)
conn.close()