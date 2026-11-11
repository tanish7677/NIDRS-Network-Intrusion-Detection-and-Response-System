# ============================================================
# NIDRS — THREAT INTELLIGENCE LOOKUP (UPGRADE — Tier 2)
# ============================================================
#
# Checks a source IP against AbuseIPDB (https://www.abuseipdb.com/)
# to see if it has been reported as malicious before. Free tier:
# 1,000 checks/day, no credit card needed.
#
# SETUP (do this on your own machine, not here):
#   1. Create a free account at https://www.abuseipdb.com/register
#   2. Get an API key from https://www.abuseipdb.com/account/api
#   3. Set it as an environment variable:
#        export NIDRS_ABUSEIPDB_KEY="your_key_here"
#
# Like geoip_lookup.py, private/LAN IPs are skipped automatically —
# AbuseIPDB has no data for internal addresses.

import os
import requests

from geoip_lookup import is_private_ip

_CACHE = {}

_API_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip_str, max_age_days=90, timeout=5):
    """
    Returns a dict:
        {
            "ip": ip_str,
            "status": "success" | "private" | "no_api_key" | "fail",
            "abuse_score": int or None,   # 0-100, higher = more malicious
            "total_reports": int or None,
            "country": str or None,
            "is_whitelisted": bool or None
        }
    """

    if not ip_str:
        return {
            "ip": ip_str, "status": "fail", "abuse_score": None,
            "total_reports": None, "country": None, "is_whitelisted": None
        }

    if ip_str in _CACHE:
        return _CACHE[ip_str]

    if is_private_ip(ip_str):
        result = {
            "ip": ip_str, "status": "private", "abuse_score": None,
            "total_reports": None, "country": None, "is_whitelisted": None
        }
        _CACHE[ip_str] = result
        return result

    api_key = os.environ.get("NIDRS_ABUSEIPDB_KEY")

    if not api_key:
        result = {
            "ip": ip_str, "status": "no_api_key", "abuse_score": None,
            "total_reports": None, "country": None, "is_whitelisted": None
        }
        _CACHE[ip_str] = result
        return result

    try:
        response = requests.get(
            _API_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip_str, "maxAgeInDays": max_age_days},
            timeout=timeout
        )

        if response.status_code != 200:
            result = {
                "ip": ip_str, "status": "fail", "abuse_score": None,
                "total_reports": None, "country": None, "is_whitelisted": None
            }
        else:
            data = response.json().get("data", {})
            result = {
                "ip": ip_str,
                "status": "success",
                "abuse_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "is_whitelisted": data.get("isWhitelisted")
            }

    except Exception:
        result = {
            "ip": ip_str, "status": "fail", "abuse_score": None,
            "total_reports": None, "country": None, "is_whitelisted": None
        }

    _CACHE[ip_str] = result
    return result


def risk_label(abuse_score):
    """Convert AbuseIPDB's 0-100 score into a human label."""

    if abuse_score is None:
        return "Unknown"

    if abuse_score >= 75:
        return "🔴 High Risk"

    if abuse_score >= 25:
        return "🟠 Suspicious"

    return "🟢 Low Risk"


if __name__ == "__main__":

    for test_ip in ["8.8.8.8", "192.168.1.10"]:
        print(test_ip, "->", check_ip_reputation(test_ip))
