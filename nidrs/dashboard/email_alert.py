import smtplib
from email.message import EmailMessage
import os


# -----------------------------
# CONFIGURATION
# -----------------------------
# FIX: credentials were hardcoded in plaintext before (a real Gmail
# address + App Password were committed directly in this file — a
# serious security exposure). They now come from environment variables.
#
# Before running, set these in your terminal (or a .env file loaded by
# your shell / IDE):
#
#   export NIDRS_SENDER_EMAIL="your_email@gmail.com"
#   export NIDRS_APP_PASSWORD="your_16_char_app_password"
#   export NIDRS_RECEIVER_EMAIL="analyst_email@gmail.com"
#
# NEVER commit real values into this file or into git.

SENDER_EMAIL = os.environ.get("NIDRS_SENDER_EMAIL")

APP_PASSWORD = os.environ.get("NIDRS_APP_PASSWORD")

RECEIVER_EMAIL = os.environ.get("NIDRS_RECEIVER_EMAIL")


# -----------------------------
# SEND EMAIL
# -----------------------------

def send_alert_email(alert, pdf_path=None):

    if not SENDER_EMAIL or not APP_PASSWORD or not RECEIVER_EMAIL:

        print(
            "Email Not Sent: NIDRS_SENDER_EMAIL / NIDRS_APP_PASSWORD / "
            "NIDRS_RECEIVER_EMAIL environment variables are not set."
        )

        return False

    msg = EmailMessage()

    msg["Subject"] = f"🚨 NIDRS Critical Alert #{alert['id']}"

    msg["From"] = SENDER_EMAIL

    msg["To"] = RECEIVER_EMAIL


    # enrichment stored with the alert (MITRE + GeoIP + AbuseIPDB)
    location = ", ".join(
        str(x) for x in (alert.get("geo_city"), alert.get("geo_country"))
        if x and str(x).lower() not in ("none", "nan")
    ) or "-"

    abuse_score = alert.get("abuse_score")
    abuse_text = (
        f"{abuse_score}%"
        if abuse_score is not None and str(abuse_score).lower() != "nan"
        else "-"
    )

    mitre_text = alert.get("mitre_technique") or "-"
    external_ip = alert.get("enriched_ip") or "-"

    body = f"""
NIDRS ALERT

Alert ID : {alert['id']}

Attack Type : {alert['attack_type']}

Severity : {alert['severity']}

Source IP : {alert.get('src_ip', '-')}

Destination IP : {alert.get('dst_ip', '-')}

External IP : {external_ip}

Location : {location}

AbuseIPDB Score : {abuse_text}

MITRE ATT&CK : {mitre_text}

Detected At :

{alert['detected_at']}

Response Status :

{alert['status']}

Please investigate immediately.

Generated Automatically by NIDRS.
"""

    msg.set_content(body)


    # Attach PDF (optional)

    if pdf_path and os.path.exists(pdf_path):

        with open(pdf_path, "rb") as f:

            msg.add_attachment(
                f.read(),
                maintype="application",
                subtype="pdf",
                filename=os.path.basename(pdf_path)
            )


    try:

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:

            smtp.login(
                SENDER_EMAIL,
                APP_PASSWORD
            )

            smtp.send_message(msg)

        print("Email Sent Successfully")

        return True


    except Exception as e:

        print(e)

        return False
