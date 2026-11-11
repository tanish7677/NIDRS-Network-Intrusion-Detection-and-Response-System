"""
NIDRS — Email Setup Test Script
================================
Sends ONE fake Critical alert email (with a PDF attached) so you can
confirm your Gmail App Password / environment variables are configured
correctly, without needing to run live packet capture or wait for a
real Critical anomaly.

USAGE:
    1. Set the 3 environment variables first (same ones email_alert.py
       reads):

           export NIDRS_SENDER_EMAIL="your_email@gmail.com"
           export NIDRS_APP_PASSWORD="your_16_char_app_password"
           export NIDRS_RECEIVER_EMAIL="analyst_email@gmail.com"

       (On Windows PowerShell use:  $env:NIDRS_SENDER_EMAIL="..."  etc.)

    2. Run this script from inside the dashboard/ folder:

           cd nidrs/dashboard
           python test_email_setup.py

    3. Check the receiver inbox (and Spam folder) for a mail titled
       "🚨 NIDRS Critical Alert #999" with Incident_999_test.pdf attached.
"""

from pathlib import Path
from datetime import datetime

from email_alert import send_alert_email
from reports.generate_pdf import create_incident_report


def main():

    print("=" * 50)
    print("NIDRS EMAIL SETUP TEST")
    print("=" * 50)

    fake_alert = {
        "id": 999,
        "attack_type": "Live Anomaly",
        "severity": "Critical",
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.99",
        "protocol": "TCP",
        "packet_count": 842,
        "total_bytes": 1204800,
        "status": "New",
        "response_action": "",
        "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    report_dir = Path(__file__).resolve().parent / "reports"
    report_dir.mkdir(exist_ok=True)

    report_path = str(report_dir / "Incident_999_test.pdf")

    print("\nGenerating test PDF report...")
    create_incident_report(fake_alert, report_path)
    print(f"PDF created: {report_path}")

    print("\nAttempting to send test email...")
    result = send_alert_email(fake_alert, report_path)

    print()
    if result:
        print("✅ SUCCESS — check the receiver inbox (and Spam folder).")
    else:
        print(
            "❌ FAILED — see the error message above.\n"
            "Common causes:\n"
            "  - NIDRS_SENDER_EMAIL / NIDRS_APP_PASSWORD / "
            "NIDRS_RECEIVER_EMAIL not set\n"
            "  - App Password is wrong, revoked, or has spaces stripped "
            "incorrectly\n"
            "  - 2-Step Verification not enabled on the Gmail account "
            "(required for App Passwords)\n"
            "  - No internet access from this machine"
        )
    print("=" * 50)


if __name__ == "__main__":
    main()
