import sqlite3


DATABASE_NAME = "alerts.db"


print()
print("=" * 50)
print("NIDRS RESPONSE ENGINE DATABASE UPGRADE")
print("=" * 50)


conn = sqlite3.connect(DATABASE_NAME)

cursor = conn.cursor()


# =========================================================
# GET EXISTING COLUMNS
# =========================================================

cursor.execute(
    "PRAGMA table_info(alerts)"
)

columns = cursor.fetchall()

existing_columns = [
    column[1]
    for column in columns
]


# =========================================================
# RESPONSE ENGINE COLUMNS
# =========================================================

new_columns = {
    "status": "TEXT DEFAULT 'New'",
    "response_action": "TEXT",
    "response_at": "TEXT"
}


# =========================================================
# ADD MISSING COLUMNS
# =========================================================

for column_name, column_type in new_columns.items():

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


# =========================================================
# UPDATE OLD ALERTS
# =========================================================

cursor.execute(
    """
    UPDATE alerts
    SET status = 'New'
    WHERE status IS NULL
    """
)

updated_rows = cursor.rowcount


# =========================================================
# SAVE DATABASE
# =========================================================

conn.commit()

conn.close()


print()
print(
    f"Old Alerts Updated: {updated_rows}"
)

print()

print(
    "Database Upgrade Completed"
)

print("=" * 50)