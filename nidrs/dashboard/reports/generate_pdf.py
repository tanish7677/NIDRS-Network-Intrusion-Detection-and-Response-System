from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import pandas as pd
import sys
from pathlib import Path

# UPGRADE (Tier 2 — MITRE ATT&CK): make mitre_mapping.py importable
# regardless of the caller's working directory (it lives in
# nidrs/response/, a sibling of nidrs/dashboard/).
_RESPONSE_DIR = str(Path(__file__).resolve().parent.parent.parent / "response")
if _RESPONSE_DIR not in sys.path:
    sys.path.insert(0, _RESPONSE_DIR)

try:
    from mitre_mapping import get_mitre_info
except ImportError:
    get_mitre_info = None


def safe(value, default="N/A"):
    """
    FIX: Dataset attacks (DoS/Probe/R2L/U2R) don't have src_ip, dst_ip,
    protocol, packet_count, total_bytes populated (those columns are only
    filled in for Live Anomaly rows). Previously those fields printed the
    literal string "nan" in the PDF. Now they show a clean "N/A" instead.
    """

    if value is None:
        return default

    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass

    return value


def create_incident_report(alert, filename):

    styles = getSampleStyleSheet()

    pdf = SimpleDocTemplate(filename)

    story = []

    story.append(Paragraph("<b>NIDRS INCIDENT REPORT</b>", styles["Title"]))

    story.append(Paragraph("<br/>", styles["Normal"]))

    fields = [
        ("Alert ID", safe(alert.get("id"))),
        ("Attack Type", safe(alert.get("attack_type"))),
        ("Severity", safe(alert.get("severity"))),
        ("Source IP", safe(alert.get("src_ip"))),
        ("Destination IP", safe(alert.get("dst_ip"))),
        ("Protocol", safe(alert.get("protocol"))),
        ("Packet Count", safe(alert.get("packet_count"))),
        ("Total Bytes", safe(alert.get("total_bytes"))),
        ("Status", safe(alert.get("status"), "New")),
        ("Response", safe(alert.get("response_action"), "")),
        ("Detected At", safe(alert.get("detected_at")))
    ]

    for key, value in fields:

        story.append(
            Paragraph(
                f"<b>{key} :</b> {value}",
                styles["BodyText"]
            )
        )

    # Automatic enrichment stored with the alert (GeoIP + AbuseIPDB)
    external_ip = safe(alert.get("enriched_ip"), None)

    if external_ip is not None or safe(alert.get("intel_status"), None):

        city = safe(alert.get("geo_city"), "")
        country = safe(alert.get("geo_country"), "")
        location = ", ".join(x for x in (city, country) if x) or "N/A"

        abuse_score = safe(alert.get("abuse_score"), None)
        abuse_reports = safe(alert.get("abuse_reports"), None)

        story.append(Paragraph("<br/>", styles["Normal"]))
        story.append(
            Paragraph("<b>Threat Intelligence</b>", styles["Heading2"])
        )

        intel_fields = [
            ("External IP", external_ip or "N/A"),
            ("GeoIP Location", location),
            (
                "AbuseIPDB Confidence Score",
                f"{abuse_score}%" if abuse_score is not None else "N/A"
            ),
            (
                "AbuseIPDB Total Reports",
                abuse_reports if abuse_reports is not None else "N/A"
            ),
            ("Lookup Status", safe(alert.get("intel_status")))
        ]

        for key, value in intel_fields:
            story.append(
                Paragraph(f"<b>{key} :</b> {value}", styles["BodyText"])
            )

    # UPGRADE (Tier 2 — MITRE ATT&CK mapping in the incident report)
    if get_mitre_info is not None:

        mitre_info = get_mitre_info(safe(alert.get("attack_type")), alert)

        story.append(Paragraph("<br/>", styles["Normal"]))
        story.append(
            Paragraph("<b>MITRE ATT&amp;CK Mapping</b>", styles["Heading2"])
        )
        story.append(
            Paragraph(
                f"<b>Technique :</b> {mitre_info['technique_id']} — "
                f"{mitre_info['technique_name']}",
                styles["BodyText"]
            )
        )
        story.append(
            Paragraph(
                f"<b>Tactic :</b> {mitre_info['tactic']}",
                styles["BodyText"]
            )
        )
        story.append(
            Paragraph(
                mitre_info["description"],
                styles["BodyText"]
            )
        )

    pdf.build(story)

    return filename
