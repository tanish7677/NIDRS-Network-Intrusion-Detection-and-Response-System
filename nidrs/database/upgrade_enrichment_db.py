"""
NIDRS - ENRICHMENT DATABASE UPGRADE
===================================
Adds the enrichment columns (external IP, GeoIP location, AbuseIPDB score,
MITRE ATT&CK technique/tactic) to the `alerts` table.

You normally do NOT need to run this by hand: every detector adds the
columns automatically the first time it stores an alert. It is provided
for completeness, like the other upgrade_*.py scripts.

    python upgrade_enrichment_db.py
    python upgrade_enrichment_db.py --backfill     # also enrich old rows
"""

import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

sys.path.insert(0, str(HERE.parent / "response"))

from enrichment import ensure_enrichment_columns, backfill

DATABASE_PATH = HERE / "alerts.db"

print()
print("=" * 50)
print("NIDRS ENRICHMENT DATABASE UPGRADE")
print("=" * 50)

conn = sqlite3.connect(str(DATABASE_PATH))
ensure_enrichment_columns(conn)
conn.commit()
conn.close()

print("Enrichment columns are present.")

if "--backfill" in sys.argv:
    backfill(DATABASE_PATH)
