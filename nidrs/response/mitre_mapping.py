# ============================================================
# NIDRS — MITRE ATT&CK MAPPING (UPGRADE — Tier 2)
# ============================================================
#
# Maps each attack category NIDRS detects to the corresponding
# MITRE ATT&CK Enterprise technique. This is a static reference
# mapping (no network calls needed), based on NSL-KDD's five
# categories and common technique classifications for the same
# underlying attack behaviour.
#
# Reference: https://attack.mitre.org/

MITRE_MAPPING = {

    "DoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "description": (
            "Adversary attempts to degrade or block the availability "
            "of a service by flooding it with traffic (e.g. neptune/"
            "SYN flood, smurf, teardrop)."
        )
    },

    "Probe": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "description": (
            "Adversary probes the network to discover live hosts, "
            "open ports, and running services before an attack "
            "(e.g. satan, ipsweep, portsweep, nmap)."
        )
    },

    "R2L": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": (
            "Remote-to-Local attack: adversary without prior access "
            "attempts to gain local access by exploiting a service or "
            "guessing credentials (e.g. guess_passwd, ftp_write, "
            "warezmaster)."
        )
    },

    "U2R": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1068/",
        "description": (
            "User-to-Root attack: adversary with local access exploits "
            "a vulnerability to gain root/administrator privileges "
            "(e.g. buffer_overflow, rootkit, loadmodule)."
        )
    },

    "Live Anomaly": {
        "technique_id": "T1046 / TA0043",
        "technique_name": "Anomalous Behaviour (Unmapped)",
        "tactic": "Reconnaissance / Unspecified",
        "url": "https://attack.mitre.org/tactics/TA0043/",
        "description": (
            "Detected by the unsupervised Isolation Forest model based "
            "on statistical deviation from normal traffic, not a "
            "labeled signature — so it cannot be mapped to one exact "
            "MITRE technique. Flagged here as unusual behaviour "
            "warranting manual triage."
        )
    }

}


DEFAULT_MAPPING = {
    "technique_id": "N/A",
    "technique_name": "Unclassified",
    "tactic": "Unknown",
    "url": "https://attack.mitre.org/",
    "description": "No MITRE ATT&CK mapping available for this attack type."
}


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def get_mitre_info(attack_type, alert=None):
    """
    Returns the MITRE ATT&CK mapping dict for a given NIDRS attack_type
    string ("DoS", "Probe", "R2L", "U2R", "Live Anomaly"). Falls back to
    DEFAULT_MAPPING for anything unrecognised (e.g. "Normal").

    The four supervised categories map directly to a technique.

    A "Live Anomaly" comes from an unsupervised model, so it has no
    attack label. If the flow itself is passed in as `alert`, a
    behaviour-based (indicative) mapping is made from the flow's traffic
    pattern; otherwise it stays "Unmapped" for manual triage.
    """

    if attack_type == "Live Anomaly" and alert is not None:

        try:
            packets_per_second = _num(alert.get("packets_per_second"))
        except AttributeError:
            packets_per_second = 0.0

        # very high packet rate -> flooding behaviour (same threshold the
        # response engine uses for its "packet flooding" rule)
        if packets_per_second > 100:

            return {
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service "
                                  "(behaviour-based, indicative)",
                "tactic": "Impact",
                "url": "https://attack.mitre.org/techniques/T1498/",
                "description": (
                    "The flow was flagged by the Isolation Forest and its "
                    "packet rate is above 100 packets/second, which is "
                    "consistent with traffic flooding. This mapping is "
                    "indicative only - the anomaly model has no attack "
                    "label - and should be confirmed by an analyst."
                )
            }

    return MITRE_MAPPING.get(attack_type, DEFAULT_MAPPING)


if __name__ == "__main__":

    for attack_type in ["DoS", "Probe", "R2L", "U2R", "Live Anomaly", "Normal"]:

        info = get_mitre_info(attack_type)

        print(f"\n{attack_type}:")
        print(f"  Technique : {info['technique_id']} — {info['technique_name']}")
        print(f"  Tactic    : {info['tactic']}")
        print(f"  URL       : {info['url']}")
