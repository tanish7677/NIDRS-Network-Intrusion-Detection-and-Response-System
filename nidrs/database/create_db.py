import sqlite3
conn = sqlite3.connect("alerts.db")
cursor = conn.cursor()
cursor.execute(
    '''CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    severity TEXT
)
''')
conn.commit()
print("DATABASE CREATED SUCCESSFULLY")
conn.close()
