# ============================================================
# NIDRS — GEOIP LOOKUP (UPGRADE — Tier 2)
# ============================================================
#
# Resolves a public IP address to an approximate country/city using
# the free ip-api.com endpoint (no API key needed, ~45 requests/min
# rate limit on the free tier — fine for a college demo).
#
# IMPORTANT: during a live capture on a college/home network, most
# captured src_ip/dst_ip values will be PRIVATE/LAN addresses
# (192.168.x.x, 10.x.x.x, 172.16-31.x.x) or loopback/link-local.
# These have NO real-world location — ip-api.com will just fail or
# return nothing useful for them. Rather than show a broken/blank
# map row, private IPs are detected up front and labeled
# "Internal Network" instead of being sent to the API at all.

import ipaddress
import requests

_CACHE = {}


def is_private_ip(ip_str):
    """
    True for private/loopback/link-local/reserved addresses that
    ip-api.com cannot meaningfully geolocate.
    """

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # not a valid IP at all — treat as non-lookupable

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    )


def lookup_ip(ip_str, timeout=3):
    """
    Returns a dict:
        {
            "ip": ip_str,
            "status": "success" | "private" | "fail",
            "country": str or None,
            "city": str or None,
            "lat": float or None,
            "lon": float or None,
            "isp": str or None
        }

    Results are cached in-process so the same IP is never looked up
    twice in one dashboard session (keeps well under the free-tier
    rate limit).
    """

    if not ip_str or pd_isna_safe(ip_str):
        return {
            "ip": ip_str, "status": "fail", "country": None,
            "city": None, "lat": None, "lon": None, "isp": None
        }

    if ip_str in _CACHE:
        return _CACHE[ip_str]

    if is_private_ip(ip_str):
        result = {
            "ip": ip_str, "status": "private", "country": "Internal Network",
            "city": "Internal Network", "lat": None, "lon": None, "isp": None
        }
        _CACHE[ip_str] = result
        return result

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_str}",
            params={"fields": "status,country,city,lat,lon,isp"},
            timeout=timeout
        )

        data = response.json()

        if data.get("status") == "success":
            result = {
                "ip": ip_str,
                "status": "success",
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp")
            }
        else:
            result = {
                "ip": ip_str, "status": "fail", "country": None,
                "city": None, "lat": None, "lon": None, "isp": None
            }

    except Exception:
        result = {
            "ip": ip_str, "status": "fail", "country": None,
            "city": None, "lat": None, "lon": None, "isp": None
        }

    _CACHE[ip_str] = result
    return result


def pd_isna_safe(value):
    """Avoids a hard pandas dependency just for a None/NaN check."""
    try:
        import math
        return value is None or (isinstance(value, float) and math.isnan(value))
    except Exception:
        return value is None


def lookup_many(ip_list):
    """
    Looks up a list of IPs and returns a list of result dicts
    (skips duplicates/None automatically via the cache + guard).
    """

    results = []

    for ip in ip_list:
        results.append(lookup_ip(ip))

    return results


if __name__ == "__main__":

    for test_ip in ["8.8.8.8", "192.168.1.10", "1.1.1.1", "10.0.0.5"]:
        print(test_ip, "->", lookup_ip(test_ip))
