# ============================================================
# NIDRS - AUTOMATIC ALERT ENRICHMENT
# ============================================================
#
# Every alert is enriched the moment it is stored in the SQLite
# database, with:
#
#   1. MITRE ATT&CK technique + tactic        (always, offline)
#   2. GeoIP location of the external IP      (ip-api.com, internet)
#   3. AbuseIPDB threat-intelligence score    (needs NIDRS_ABUSEIPDB_KEY)
#
# The results are written into extra columns of the `alerts` table, so
# the dashboard, the incident PDF and the alert email all read the same
# stored values.
#
# Which IP is looked up?  A flow has two endpoints and one of them is
# normally on the local network. The first PUBLIC address (source first,
# then destination) is used. Dataset alerts have no IP at all, so they
# only receive the MITRE mapping.
#
# Enrichment never stops detection: any failure is caught and stored as
# an "intel_status" note instead of raising an error.
#
# Back-fill old rows (run on a machine with internet access):
#     python enrichment.py --backfill ../database/alerts.db
#     python enrichment.py --backfill ../database/alerts.db --force

import sqlite3
import sys
from datetime import datetime
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import geoip_lookup as _geoip_module
import threat_intel as _intel_module
from mitre_mapping import get_mitre_info
from geoip_lookup import lookup_ip, is_private_ip
from threat_intel import check_ip_reputation


ENRICHMENT_COLUMNS = {
    "enriched_ip": "TEXT",
    "geo_country": "TEXT",
    "geo_city": "TEXT",
    "abuse_score": "INTEGER",
    "abuse_reports": "INTEGER",
    "intel_status": "TEXT",
    "mitre_technique": "TEXT",
    "mitre_tactic": "TEXT",
}


def _clean(value):
    """None / NaN / empty -> None, anything else -> str."""

    if value is None:
        return None

    try:
        if value != value:          # NaN
            return None
    except Exception:
        pass

    text = str(value).strip()

    return text or None


def pick_external_ip(alert):
    """First public IP of the flow (source first, then destination)."""

    for key in ("src_ip", "dst_ip"):

        ip = _clean(alert.get(key))

        if ip and not is_private_ip(ip):
            return ip

    return None


def has_any_ip(alert):
    return bool(_clean(alert.get("src_ip")) or _clean(alert.get("dst_ip")))


def enrich_alert(alert, do_lookups=True):
    """
    Returns a dict with every key of ENRICHMENT_COLUMNS.
    `alert` can be a dict or a pandas row (anything with .get()).
    """

    attack_type = _clean(alert.get("attack_type")) or "Unknown"

    mitre = get_mitre_info(attack_type, alert)

    result = {
        "enriched_ip": None,
        "geo_country": None,
        "geo_city": None,
        "abuse_score": None,
        "abuse_reports": None,
        "intel_status": None,
        "mitre_technique": f"{mitre['technique_id']} - {mitre['technique_name']}",
        "mitre_tactic": mitre["tactic"],
    }

    external_ip = pick_external_ip(alert)

    if external_ip is None:

        result["intel_status"] = (
            "internal-only" if has_any_ip(alert) else "no-ip"
        )

        return result

    result["enriched_ip"] = external_ip

    if not do_lookups:
        result["intel_status"] = "pending"
        return result

    try:
        geo = lookup_ip(external_ip)
    except Exception:
        geo = {"status": "fail", "country": None, "city": None}

    try:
        intel = check_ip_reputation(external_ip)
    except Exception:
        intel = {"status": "fail", "abuse_score": None, "total_reports": None}

    # do not let a temporary network failure stay cached for the whole
    # lifetime of a long-running monitor - retry on the next alert
    if geo.get("status") == "fail":
        _geoip_module._CACHE.pop(external_ip, None)

    if intel.get("status") == "fail":
        _intel_module._CACHE.pop(external_ip, None)

    if geo.get("status") == "success":
        result["geo_country"] = geo.get("country")
        result["geo_city"] = geo.get("city")

    if intel.get("status") == "success":
        result["abuse_score"] = intel.get("abuse_score")
        result["abuse_reports"] = intel.get("total_reports")

    result["intel_status"] = (
        f"geoip:{geo.get('status')}; abuseipdb:{intel.get('status')}"
    )

    return result


# ------------------------------------------------------------
# DATABASE HELPERS
# ------------------------------------------------------------

def ensure_enrichment_columns(conn):
    """Adds the enrichment columns if the table does not have them yet."""

    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(alerts)")

    existing = {row[1] for row in cursor.fetchall()}

    for name, column_type in ENRICHMENT_COLUMNS.items():

        if name not in existing:
            cursor.execute(
                f"ALTER TABLE alerts ADD COLUMN {name} {column_type}"
            )


def store_enrichment(conn, alert_id, enrichment):

    names = list(ENRICHMENT_COLUMNS)

    assignments = ", ".join(f"{n} = ?" for n in names)

    conn.execute(
        f"UPDATE alerts SET {assignments} WHERE id = ?",
        [enrichment[n] for n in names] + [alert_id],
    )


def enrich_and_store(conn, alert_id, alert, do_lookups=True):
    """
    Enrich one freshly inserted alert and save the result on its row.
    Returns the enrichment dict (empty dict if something went wrong, so
    callers can always do alert_row.update(result)).
    """

    try:
        ensure_enrichment_columns(conn)

        enrichment = enrich_alert(alert, do_lookups=do_lookups)

        store_enrichment(conn, alert_id, enrichment)

        return enrichment

    except Exception as error:

        print(f"[enrichment] skipped for alert {alert_id}: {error}")

        return {}


def backfill(db_path, force=False):
    """Enrich rows that were stored before enrichment existed."""

    conn = sqlite3.connect(str(db_path))

    conn.row_factory = sqlite3.Row

    ensure_enrichment_columns(conn)

    rows = conn.execute("SELECT * FROM alerts").fetchall()

    done = 0

    for row in rows:

        alert = dict(row)

        needs = (
            force
            or alert.get("mitre_technique") is None
            or (
                pick_external_ip(alert) is not None
                and (
                    alert.get("intel_status") is None
                    or "fail" in str(alert.get("intel_status"))
                    or "pending" in str(alert.get("intel_status"))
                )
            )
        )

        if not needs:
            continue

        store_enrichment(conn, alert["id"], enrich_alert(alert))

        done += 1

    conn.commit()
    conn.close()

    print(f"Enriched {done} of {len(rows)} alerts "
          f"({datetime.now():%Y-%m-%d %H:%M:%S}).")


if __name__ == "__main__":

    if "--backfill" in sys.argv:

        position = sys.argv.index("--backfill")

        target = (
            sys.argv[position + 1]
            if len(sys.argv) > position + 1
            and not sys.argv[position + 1].startswith("--")
            else _HERE.parent / "database" / "alerts.db"
        )

        backfill(target, force="--force" in sys.argv)

    else:

        demo = {
            "attack_type": "Live Anomaly",
            "src_ip": "192.168.1.19",
            "dst_ip": "8.8.8.8",
            "packets_per_second": 150,
        }

        print(enrich_alert(demo))
