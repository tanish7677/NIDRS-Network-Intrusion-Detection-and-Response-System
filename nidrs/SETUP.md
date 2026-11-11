# NIDRS — Setup Guide

## 1. Install dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

(Drop `--break-system-packages` if you're using a virtual environment,
which is recommended: `python -m venv venv` then activate it first.)

## 2. Environment variables

Set these before running the dashboard or any of the model/model
scripts. On Windows (PowerShell), use `$env:NAME="value"` instead of
`export NAME="value"`. For values that should persist across
terminal sessions, set them via Windows "Environment Variables"
settings instead (see the chat history for the click-path).

| Variable | Required for | Where to get it |
|---|---|---|
| `NIDRS_SENDER_EMAIL` | Email alerts | Your Gmail address |
| `NIDRS_APP_PASSWORD` | Email alerts | Google Account → Security → 2-Step Verification → App Passwords (2-Step Verification must be ON first) |
| `NIDRS_RECEIVER_EMAIL` | Email alerts | Whichever inbox should receive Critical alerts |
| `NIDRS_ABUSEIPDB_KEY` | Threat Intelligence lookup (Tier 2) | Free account at https://www.abuseipdb.com/register → https://www.abuseipdb.com/account/api |

GeoIP lookups (Tier 2) need no key — they use the free, no-auth
`ip-api.com` endpoint.

## 3. Verify email works before the demo

```bash
cd nidrs/dashboard
python test_email_setup.py
```

Should print `✅ SUCCESS`. If not, see the troubleshooting notes in
the chat history (usually: 2-Step Verification not enabled yet, or a
regular password used instead of an App Password).

## 3b. Retrain the models once (SMOTE + consistent encoders)

The multiclass Random Forest is now ALWAYS trained with SMOTE (it uses
`imbalanced-learn` if installed, otherwise the built-in version in
`model/smote_utils.py`). Run this once after copying the project:

```
python retrain_all.py
```

Look for `SMOTE applied using: ...` in the output of the first step.

## 3c. Automatic alert enrichment

Every new alert (live and dataset) is enriched automatically when it is
stored in `alerts.db` (`response/enrichment.py`):

| Enrichment | Needs | Notes |
|---|---|---|
| MITRE ATT&CK technique + tactic | nothing | offline; live anomalies are mapped from flow behaviour (indicative) |
| GeoIP location | internet | ip-api.com, public IPs only |
| AbuseIPDB score | `NIDRS_ABUSEIPDB_KEY` + internet | public IPs only |

The first PUBLIC address of a flow (source, then destination) is looked
up. Private/LAN addresses are labelled `internal-only`; dataset alerts have
no IP and only get the MITRE mapping. Results are stored in the alert row
and shown in Response Center, the incident PDF and the alert email.

Alerts stored before this feature (or while offline) can be enriched later:

```
python response/enrichment.py --backfill
```

## 4. Run the dashboard

```bash
cd nidrs/dashboard
streamlit run app.py
```

Login: `admin` / `admin123` (see note below on changing this).

## 5. Populate some data before the demo

- **Dataset-side alerts:** `cd nidrs/model && python auto_alerts.py`
  (needs `KDDTest+.txt` in that folder)
- **Live anomalies:** use the "▶ Run Live Detection" button on the
  Dashboard page, or "▶ Start Continuous Monitoring" for the Tier 2
  rolling-window version. Packet capture usually needs the terminal /
  IDE to be run as Administrator (Windows) or with `sudo` (Linux/Mac).

## 6. Known limitations to mention in the demo (shows maturity, not weakness)

- Live capture on a college/home network mostly sees **private IPs**
  (192.168.x.x etc.) — these have no real-world GeoIP location and
  are labeled "Internal Network" instead of being plotted on the map.
- The class-imbalance fix (SMOTE) can have high variance on the U2R
  class specifically, because NSL-KDD only has ~52 U2R samples total.
- Login credentials (`admin`/`admin123`) are hardcoded for demo
  simplicity — flag this as a "future work: proper auth" item if
  asked, rather than presenting it as production-ready.
