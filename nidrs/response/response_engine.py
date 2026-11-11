# ============================================================
# NIDRS AUTOMATED RESPONSE RECOMMENDATION ENGINE
# ============================================================

from mitre_mapping import get_mitre_info


def safe_number(value, default=0):
    """
    Convert database values safely into float.
    """

    try:
        if value is None:
            return default

        number = float(value)

        # dataset alerts have no ports/flow data: the database returns
        # NaN for them, and int(NaN) used to crash the Response Center
        if number != number:
            return default

        return number

    except (ValueError, TypeError):
        return default


# Ordered worst-to-best so the final risk_level is always the
# most severe signal detected, instead of whichever check ran last.
_RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM-HIGH", "MEDIUM", "LOW"]


def _more_severe(a, b):
    return _RISK_ORDER.index(a) < _RISK_ORDER.index(b)


# ============================================================
# RESPONSE RECOMMENDATION ENGINE
# ============================================================

def generate_response_recommendation(alert):

    severity = str(alert.get("severity", "Unknown"))

    src_ip = str(alert.get("src_ip", "Unknown"))
    dst_ip = str(alert.get("dst_ip", "Unknown"))

    src_port = safe_number(alert.get("src_port"))
    dst_port = safe_number(alert.get("dst_port"))

    packet_count = safe_number(alert.get("packet_count"))
    total_bytes = safe_number(alert.get("total_bytes"))

    duration = safe_number(alert.get("duration"))

    packets_per_second = safe_number(
        alert.get("packets_per_second")
    )

    bytes_per_second = safe_number(
        alert.get("bytes_per_second")
    )

    average_packet_size = safe_number(
        alert.get("average_packet_size")
    )


    # ========================================================
    # FIX: every matching condition below used to be its own
    # independent "if" block, so later checks silently OVERWROTE
    # the risk_level/recommended_action/reason set by earlier ones
    # (e.g. a severity="Critical" alert that also had a high packet
    # rate would lose its "AI classified this as critical" reasoning,
    # replaced by the generic flooding message).
    #
    # Now every matching signal is collected into `triggered_reasons`
    # and `suggested_responses` is the UNION of all matched checks,
    # while risk_level is the single MOST SEVERE signal found.
    # ========================================================

    risk_level = "MEDIUM"

    recommended_action = (
        f"Monitor network activity from source IP {src_ip}"
    )

    triggered_reasons = []

    suggested_responses = [
        "Inspect source IP activity",
        "Monitor repeated network connections",
        "Review destination network traffic"
    ]


    # ---- CRITICAL FLOW ANALYSIS (AI-flagged severity) ----

    if severity.lower() == "critical":

        if _more_severe("HIGH", risk_level):
            risk_level = "HIGH"

        recommended_action = (
            f"Immediately investigate source IP {src_ip}"
        )

        triggered_reasons.append(
            "The anomaly detection system classified this "
            "network flow as critical."
        )

        suggested_responses = [
            f"Investigate source IP {src_ip}",
            f"Review traffic sent to destination IP {dst_ip}",
            "Monitor repeated anomalous connections",
            "Consider temporary host isolation if anomalies continue"
        ]


    # ---- HIGH PACKET RATE ----

    if packets_per_second > 100:

        if _more_severe("CRITICAL", risk_level):
            risk_level = "CRITICAL"

        recommended_action = (
            f"Investigate possible packet flooding from {src_ip}"
        )

        triggered_reasons.append(
            "Extremely high packet transmission rate detected. "
            "This behaviour may indicate network flooding."
        )

        suggested_responses += [
            "Inspect packet transmission rate",
            "Apply rate limiting if behaviour continues",
            "Consider temporary network isolation"
        ]


    # ---- HIGH BANDWIDTH FLOW ----

    elif bytes_per_second > 100000:

        if _more_severe("HIGH", risk_level):
            risk_level = "HIGH"

        recommended_action = (
            f"Investigate high bandwidth traffic from {src_ip}"
        )

        triggered_reasons.append(
            "The network flow generated an unusually high "
            "amount of traffic per second."
        )

        suggested_responses += [
            "Inspect network bandwidth usage",
            "Check for possible data transfer anomalies"
        ]


    # ---- LARGE PACKET SIZE ----

    elif average_packet_size > 1500:

        if _more_severe("HIGH", risk_level):
            risk_level = "HIGH"

        recommended_action = (
            f"Inspect abnormal packet sizes from {src_ip}"
        )

        triggered_reasons.append(
            "The average packet size is unusually large "
            "compared with typical network traffic."
        )

        suggested_responses += [
            "Inspect packet size distribution",
            "Investigate repeated large packet transfers"
        ]


    # ---- LARGE PACKET VOLUME ----

    elif packet_count > 500:

        if _more_severe("HIGH", risk_level):
            risk_level = "HIGH"

        recommended_action = (
            f"Monitor high-volume network flow from {src_ip}"
        )

        triggered_reasons.append(
            "A large number of packets were observed "
            "within a single network flow."
        )

        suggested_responses += [
            "Inspect packet volume",
            "Check destination traffic behaviour"
        ]


    # ---- SHORT BURST ANOMALY ----

    elif duration < 1 and packet_count > 20:

        if _more_severe("HIGH", risk_level):
            risk_level = "HIGH"

        recommended_action = (
            f"Investigate burst traffic from source IP {src_ip}"
        )

        triggered_reasons.append(
            "A high number of packets were transmitted "
            "within a very short network duration."
        )

        suggested_responses += [
            "Inspect burst traffic behaviour",
            "Check for repeated short-duration flows"
        ]


    if not triggered_reasons:

        reason = (
            "Abnormal network flow behaviour was detected "
            "by the anomaly detection model."
        )

    else:

        reason = " ".join(triggered_reasons)

    # de-duplicate while preserving order
    suggested_responses = list(dict.fromkeys(suggested_responses))


    # ========================================================
    # MITRE ATT&CK MAPPING (UPGRADE — Tier 2)
    # ========================================================

    attack_type = str(alert.get("attack_type", "Unknown"))

    mitre_info = get_mitre_info(attack_type, alert)

    # ========================================================
    # RESPONSE RESULT
    # ========================================================

    recommendation = {

        "risk_level": risk_level,

        "recommended_action": recommended_action,

        "reason": reason,

        "suggested_responses": suggested_responses,

        "mitre_attack": mitre_info,

        "flow_summary": {

            "source_ip": src_ip,

            "destination_ip": dst_ip,

            "source_port": int(src_port),

            "destination_port": int(dst_port),

            "packet_count": int(packet_count),

            "total_bytes": int(total_bytes),

            "duration": round(duration, 4),

            "packets_per_second": round(
                packets_per_second,
                2
            ),

            "bytes_per_second": round(
                bytes_per_second,
                2
            ),

            "average_packet_size": round(
                average_packet_size,
                2
            )

        }

    }

    return recommendation


# ============================================================
# TEST ENGINE
# ============================================================

if __name__ == "__main__":

    test_alert = {

        "severity": "Critical",

        "src_ip": "192.168.1.9",

        "dst_ip": "104.16.34.15",

        "src_port": 60024,

        "dst_port": 443,

        "packet_count": 100,

        "total_bytes": 108315,

        "duration": 3.4517,

        "packets_per_second": 128.9716,   # deliberately also triggers the packet-rate rule

        "bytes_per_second": 31380.6081,

        "average_packet_size": 1083.15

    }


    result = generate_response_recommendation(
        test_alert
    )


    print("\n" + "=" * 60)

    print("NIDRS AUTOMATED RESPONSE RECOMMENDATION")

    print("=" * 60)


    print(
        "\nRisk Level:",
        result["risk_level"]
    )


    print(
        "\nRecommended Action:"
    )

    print(
        result["recommended_action"]
    )


    print(
        "\nReason:"
    )

    print(
        result["reason"]
    )


    print(
        "\nSuggested Responses:"
    )


    for action in result["suggested_responses"]:

        print(
            "-",
            action
        )


    print("\n" + "=" * 60)
