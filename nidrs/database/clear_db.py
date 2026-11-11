import sqlite3

# FIX: was "../database/alerts.db" (inconsistent with every other script
# in this folder, which just use "alerts.db"). This only worked by
# coincidence when run from inside the database/ folder. Now consistent.
conn = sqlite3.connect("alerts.db")

cursor = conn.cursor()

cursor.execute("DELETE FROM alerts")

conn.commit()

conn.close()

print("Database Cleared")
