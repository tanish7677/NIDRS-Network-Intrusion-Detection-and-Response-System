import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import subprocess
from streamlit_autorefresh import st_autorefresh

from pathlib import Path
from datetime import datetime
import os

from reports.generate_pdf import create_incident_report
from email_alert import send_alert_email

# FIX: app.py previously defined its OWN generate_response_recommendation()
# below (a simpler version that only looks at severity), while a more
# complete version already existed in response_engine.py (also checking
# packet rate, bandwidth, packet size, and burst behaviour). The better
# engine was never actually wired in — the dashboard was silently using
# the weaker logic. Now the real response engine is imported and used.
import sys as _sys
_RESPONSE_ENGINE_DIR = str(Path(__file__).resolve().parent.parent / "response")
if _RESPONSE_ENGINE_DIR not in _sys.path:
    _sys.path.insert(0, _RESPONSE_ENGINE_DIR)

from response_engine import generate_response_recommendation

# UPGRADE (Tier 2 — GeoIP map)
from geoip_lookup import lookup_many

# UPGRADE (Tier 2 — Threat Intelligence)
from threat_intel import check_ip_reputation, risk_label

# NIDRS visual toolkit (theme, KPI cards, banners, tables, charts)
import ui


# =========================================================
# STREAMLIT CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="NIDRS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================
# 🎨 NIDRS SOC COMMAND CENTER THEME
# =========================================================
# Design direction: a dark network-operations console — deep navy
# base, electric-cyan signal accent (the "line on the radar"), with
# monospace type for anything data-like (IPs, IDs, metrics, ports) so
# it reads like a real telemetry readout rather than a generic
# dashboard template. One signature move: a slow cyan "scan sweep"
# across the very top of the page, echoing the live packet-scanning
# nature of the tool — restrained everywhere else.

# All colours, cards, sidebar and component styling live in ui.py
ui.inject_theme()


# Auto refresh every 5 seconds
st_autorefresh(
    interval=5000,
    key="dashboard_refresh"
)

# =========================================================
# PROJECT PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = (
    BASE_DIR.parent
    / "database"
    / "alerts.db"
)

LIVE_DETECTOR_PATH = (
    BASE_DIR.parent
    / "data"
    / "live_detector.py"
)


# =========================================================
# DATABASE FUNCTIONS
# =========================================================

def load_alerts():

    conn = sqlite3.connect(DATABASE_PATH)

    all_alerts = pd.read_sql_query(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        """,
        conn
    )

    dataset_alerts = pd.read_sql_query(
        """
        SELECT *
        FROM alerts
        WHERE attack_type != 'Live Anomaly'
        ORDER BY id DESC
        """,
        conn
    )

    live_alerts = pd.read_sql_query(
        """
        SELECT *
        FROM alerts
        WHERE attack_type = 'Live Anomaly'
        ORDER BY id DESC
        """,
        conn
    )

    critical_alerts = pd.read_sql_query(
        """
        SELECT *
        FROM alerts
        WHERE severity = 'Critical'
        ORDER BY id DESC
        """,
        conn
    )

    conn.close()

    return (
        all_alerts,
        dataset_alerts,
        live_alerts,
        critical_alerts
    )


def update_alert_response(
    alert_id,
    status,
    response_action
):

    conn = sqlite3.connect(DATABASE_PATH)

    cursor = conn.cursor()

    response_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute(
        """
        UPDATE alerts

        SET
            status = ?,
            response_action = ?,
            response_at = ?

        WHERE id = ?
        """,
        (
            status,
            response_action,
            response_time,
            alert_id
        )
    )

    conn.commit()

    conn.close()


# =========================================================
# AUTOMATED RESPONSE RECOMMENDATION ENGINE
# =========================================================
#
# FIX: the duplicate, weaker version of generate_response_recommendation()
# that used to live here has been removed. The dashboard now uses the
# real response engine imported from response_engine.py at the top of
# this file (it also considers packet rate, bandwidth, packet size, and
# burst behaviour, not just severity).



# =========================================================
# LOGIN SESSION
# =========================================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

def login_screen():

    ui.login_header()

    _left, _middle, _right = st.columns([1, 1.1, 1])

    with _middle:

        with st.form("login_form"):

            st.markdown("**Sign in to continue**")

            username = st.text_input("Username")

            password = st.text_input("Password", type="password")

            submitted = st.form_submit_button(
                "Sign in",
                use_container_width=True,
                type="primary"
            )

            if submitted:

                if username == "admin" and password == "admin123":

                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.rerun()

                else:
                    st.error("Invalid username or password.")


if not st.session_state.logged_in:
    login_screen()
    st.stop()


# =========================================================
# SIDEBAR
# =========================================================

ui.sidebar_brand()

PAGES = [
    "Dashboard",
    "Dataset Attacks",
    "Live Anomalies",
    "Response Center",
    "Response History",
    "📈 Analytics",
    "System Architecture",
    "Logs",
    "Settings"
]

page = st.sidebar.radio(
    "Navigation",
    PAGES,
    format_func=ui.nav_label,
    label_visibility="collapsed"
)


# =========================================================
# LOAD DATABASE
# =========================================================

(
    all_alerts,
    dataset_alerts,
    live_alerts,
    critical_alerts
) = load_alerts()


# =========================================================
# SIDEBAR - SYSTEM STATUS & ACCOUNT
# =========================================================

_last_alert_time = (
    pd.to_datetime(all_alerts["detected_at"], errors="coerce").max()
    if "detected_at" in all_alerts.columns and len(all_alerts) > 0
    else None
)

ui.sidebar_status(
    len(all_alerts),
    _last_alert_time,
    ui.monitor_status(
        BASE_DIR.parent / "data" / ".continuous_monitor.lock"
    )[0]
)

if ui.sidebar_user(st.session_state.get("username", "admin")):

    st.session_state.logged_in = False
    st.rerun()


# =========================================================
# TIMESTAMP PROCESSING
# =========================================================

if "detected_at" in all_alerts.columns:

    all_alerts["detected_at"] = pd.to_datetime(
        all_alerts["detected_at"],
        errors="coerce"
    )


if "detected_at" in live_alerts.columns:

    live_alerts["detected_at"] = pd.to_datetime(
        live_alerts["detected_at"],
        errors="coerce"
    )


if "detected_at" in critical_alerts.columns:

    critical_alerts["detected_at"] = pd.to_datetime(
        critical_alerts["detected_at"],
        errors="coerce"
    )


# =========================================================
# RECENT LIVE ALERTS
# =========================================================

current_time = pd.Timestamp.now()

if (
    "detected_at" in live_alerts.columns
    and len(live_alerts) > 0
):

    recent_live_alerts = live_alerts[
        live_alerts["detected_at"]
        >= current_time - pd.Timedelta(minutes=5)
    ].copy()

else:

    recent_live_alerts = pd.DataFrame(
        columns=live_alerts.columns
    )


# =========================================================
# SEVERITY-AWARE THREAT ENGINE
# =========================================================

recent_critical_count = len(
    recent_live_alerts[
        recent_live_alerts["severity"] == "Critical"
    ]
)

recent_high_count = len(
    recent_live_alerts[
        recent_live_alerts["severity"] == "High"
    ]
)

recent_medium_count = len(
    recent_live_alerts[
        recent_live_alerts["severity"] == "Medium"
    ]
)


if recent_critical_count > 0:

    threat_level = "CRITICAL"

elif recent_high_count > 0:

    threat_level = "HIGH"

elif recent_medium_count > 0:

    threat_level = "MEDIUM"

else:

    threat_level = "LOW"


# =========================================================
# DASHBOARD PAGE
# =========================================================

if page == "Dashboard":

    _monitor_running, _monitor_meta = ui.monitor_status(
        BASE_DIR.parent / "data" / ".continuous_monitor.lock"
    )

    _threat_kind = {
        "CRITICAL": "danger",
        "HIGH": "high",
        "MEDIUM": "warn",
        "LOW": "ok"
    }[threat_level]

    ui.page_header(
        "Security Operations Dashboard",
        "Real-time overview of detected attacks and anomalous "
        "network activity",
        icon="🛡️",
        chips=[
            (f"Threat level: {threat_level}", _threat_kind),
            (
                "Monitor running" if _monitor_running else "Monitor idle",
                "ok" if _monitor_running else "",
                _monitor_running
            ),
            (f"Updated {datetime.now():%H:%M:%S}", "info")
        ]
    )

    ui.status_banner(threat_level, recent_critical_count)

    _severity_totals = (
        all_alerts["severity"].value_counts()
        if "severity" in all_alerts.columns
        else pd.Series(dtype=int)
    )

    _awaiting_response = (
        int((all_alerts["status"] == "New").sum())
        if "status" in all_alerts.columns
        else 0
    )

    ui.kpi_row([
        {
            "label": "Total Alerts",
            "value": len(all_alerts),
            "sub": "All stored alerts",
            "color": "#3B82F6",
            "icon": "🚨"
        },
        {
            "label": "Critical",
            "value": int(_severity_totals.get("Critical", 0)),
            "sub": "Need immediate action",
            "color": ui.SEVERITY_COLORS["Critical"],
            "icon": "🔥"
        },
        {
            "label": "High",
            "value": int(_severity_totals.get("High", 0)),
            "sub": "High-severity alerts",
            "color": ui.SEVERITY_COLORS["High"],
            "icon": "⚠️"
        },
        {
            "label": "Dataset Attacks",
            "value": len(dataset_alerts),
            "sub": "Random Forest classification",
            "color": "#8B5CF6",
            "icon": "🧪"
        },
        {
            "label": "Live Anomalies",
            "value": len(live_alerts),
            "sub": f"{len(recent_live_alerts)} in the last 5 minutes",
            "color": "#14B8A6",
            "icon": "🌐"
        },
        {
            "label": "Awaiting Response",
            "value": _awaiting_response,
            "sub": "Status: New",
            "color": "#F59E0B",
            "icon": "⏳"
        }
    ])



    # =====================================================
    # LIVE DETECTION CONTROL
    # =====================================================

    st.subheader("🎯 Live Detection Control")

    col1, col2 = st.columns(
        [1, 3]
    )

    with col1:

        run_detection = st.button(
            "▶ Run Live Detection",
            use_container_width=True,
            type="primary"
        )

    with col2:

        st.info(
            "Capture 500 live network packets and analyse "
            "network flows using the Isolation Forest model."
        )


    # =====================================================
    # CONTINUOUS MONITORING (UPGRADE — Tier 2)
    # =====================================================
    # Runs data/continuous_detector.py as a background OS process
    # (not blocking the dashboard) that keeps capturing rolling
    # windows of traffic and inserting/emailing Critical anomalies
    # on its own, until a stop flag file is created.

    st.divider()
    st.subheader("🔁 Continuous Monitoring")

    _CONTINUOUS_SCRIPT = BASE_DIR.parent / "data" / "continuous_detector.py"
    _LOCK_FILE = BASE_DIR.parent / "data" / ".continuous_monitor.lock"
    _STOP_FLAG_FILE = BASE_DIR.parent / "data" / ".continuous_monitor.stop"

    def _monitor_is_running():
        """Alive if the lock file exists AND its heartbeat is recent."""

        if not _LOCK_FILE.exists():
            return False, {}

        try:
            lines = _LOCK_FILE.read_text().strip().split("\n")
            info = dict(line.split("=", 1) for line in lines if "=" in line)
            last_heartbeat = datetime.fromisoformat(info["last_heartbeat"])
            is_alive = (datetime.now() - last_heartbeat).total_seconds() < 30
            return is_alive, info
        except Exception:
            return False, {}

    is_running, monitor_info = _monitor_is_running()

    mon_col1, mon_col2, mon_col3 = st.columns([1, 1, 2])

    with mon_col1:

        start_disabled = is_running

        if st.button(
            "▶ Start Continuous Monitoring",
            disabled=start_disabled,
            use_container_width=True
        ):
            subprocess.Popen(
                ["python", str(_CONTINUOUS_SCRIPT), "--cycle-seconds", "10"],
                cwd=str(_CONTINUOUS_SCRIPT.parent)
            )
            st.info(
                "Started — this runs in the background. Refresh in a "
                "few seconds to see its status."
            )

    with mon_col2:

        if st.button(
            "⏹ Stop Continuous Monitoring",
            disabled=not is_running,
            use_container_width=True
        ):
            _STOP_FLAG_FILE.touch()
            st.info(
                "Stop requested — it will exit after its current "
                "capture cycle (up to ~10s)."
            )

    with mon_col3:

        if is_running:
            st.markdown(
                f'<span class="nidrs-pulse"></span>'
                f'<b>Running</b> — {monitor_info.get("cycles_completed", "?")} '
                f'cycle(s) completed, '
                f'{monitor_info.get("anomalies_found", "?")} anomaly(ies) '
                f'found so far.',
                unsafe_allow_html=True
            )
        else:
            st.caption(
                "⚪ Not running. Captures a rolling 10-second traffic "
                "window every cycle instead of a single fixed batch."
            )


    if run_detection:

        # FIX (gap #2): capture the highest alert id BEFORE running
        # detection, so afterwards we can find every NEW row this run
        # inserted, instead of only ever looking at the single latest
        # row in the whole table (which missed earlier Critical alerts
        # whenever a run produced more than one).
        previous_max_id = (
            int(all_alerts["id"].max())
            if len(all_alerts) > 0
            else 0
        )

        with st.spinner(
            "Capturing and analysing live network traffic..."
        ):

            try:

                result = subprocess.run(
                    [
                        "python",
                        str(LIVE_DETECTOR_PATH)
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(
                        LIVE_DETECTOR_PATH.parent
                    )
                )


                if result.returncode == 0:

                    st.success(
                        "Live network detection completed."
                    )

                    try:
                        refreshed_alerts, _, _, _ = load_alerts()

                        # FIX (gap #2): loop over EVERY Critical Live
                        # Anomaly inserted during this run (id greater
                        # than what existed before), not just
                        # refreshed_alerts.iloc[0].
                        new_critical_alerts = refreshed_alerts[
                            (refreshed_alerts["id"] > previous_max_id)
                            & (refreshed_alerts["attack_type"] == "Live Anomaly")
                            & (refreshed_alerts["severity"] == "Critical")
                        ]

                        if len(new_critical_alerts) == 0:

                            st.info(
                                "No new Critical anomalies detected in this run."
                            )

                        else:

                            report_dir = BASE_DIR / "reports"
                            report_dir.mkdir(exist_ok=True)

                            sent_count = 0
                            failed_count = 0

                            for _, alert_row in new_critical_alerts.iterrows():

                                report_path = str(
                                    report_dir / f"Incident_{alert_row['id']}.pdf"
                                )

                                create_incident_report(
                                    alert_row,
                                    report_path
                                )

                                email_sent = send_alert_email(
                                    alert_row,
                                    report_path
                                )

                                if email_sent:
                                    sent_count += 1
                                else:
                                    failed_count += 1

                            if sent_count > 0:
                                st.success(
                                    f"📧 Sent {sent_count} Critical Alert email(s)."
                                )

                            if failed_count > 0:
                                st.error(
                                    f"❌ {failed_count} Critical Alert email(s) "
                                    "could not be sent (check email "
                                    "configuration)."
                                )

                    except Exception as email_error:
                        st.warning(f"Email Notification Failed: {email_error}")

                    with st.expander(
                        "View Detection Output"
                    ):

                        st.code(
                            result.stdout
                        )


                    st.rerun()


                else:

                    st.error(
                        "Live detector execution failed."
                    )

                    st.code(
                        result.stderr
                    )


            except Exception as error:

                st.error(
                    f"Detector Error: {error}"
                )


    st.divider()


    # =====================================================
    # THREAT OVERVIEW (charts)
    # =====================================================

    ui.section(
        "📊 Threat Overview",
        "Distribution and trend of every stored alert"
    )

    if len(all_alerts) > 0:

        chart_left, chart_right = st.columns(2)

        with chart_left:

            attack_counts = (
                all_alerts["attack_type"]
                .value_counts()
                .reset_index()
            )

            attack_counts.columns = ["Attack Type", "Count"]

            fig = px.pie(
                attack_counts,
                names="Attack Type",
                values="Count",
                title="Alert type distribution",
                hole=0.55
            )

            fig.update_traces(
                textinfo="percent",
                marker=dict(line=dict(color="#111A2C", width=2))
            )

            ui.plotly_chart(fig)

        with chart_right:

            severity_counts = (
                all_alerts["severity"]
                .value_counts()
                .reset_index()
            )

            severity_counts.columns = ["Severity", "Count"]

            fig2 = px.bar(
                severity_counts,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map=ui.SEVERITY_COLORS,
                category_orders={
                    "Severity": ["Critical", "High", "Medium", "Low"]
                },
                text="Count",
                title="Severity distribution"
            )

            fig2.update_traces(textposition="outside")

            fig2.update_layout(showlegend=False)

            ui.plotly_chart(fig2)

        if "detected_at" in all_alerts.columns:

            timeline_df = all_alerts.copy()

            timeline_df["detected_at"] = pd.to_datetime(
                timeline_df["detected_at"],
                errors="coerce"
            )

            timeline_df = timeline_df.dropna(subset=["detected_at"])

            if len(timeline_df) > 0:

                time_span = (
                    timeline_df["detected_at"].max()
                    - timeline_df["detected_at"].min()
                )

                if time_span <= pd.Timedelta(hours=3):
                    bucket = "1min"
                elif time_span <= pd.Timedelta(days=3):
                    bucket = "1h"
                else:
                    bucket = "1D"

                timeline = (
                    timeline_df
                    .groupby([
                        pd.Grouper(key="detected_at", freq=bucket),
                        "attack_type"
                    ])
                    .size()
                    .reset_index(name="Alerts")
                )

                fig3 = px.bar(
                    timeline,
                    x="detected_at",
                    y="Alerts",
                    color="attack_type",
                    title="Alerts over time",
                    labels={
                        "detected_at": "Time",
                        "attack_type": "Attack type"
                    }
                )

                ui.plotly_chart(fig3)

            else:
                st.info("No timeline data available.")

    else:
        st.info("No alerts available yet. Run a detection to begin.")

    # =====================================================
    # LIVE NETWORK STATUS
    # =====================================================

    st.divider()

    st.subheader(
        "🌐 Live Network Security Status"
    )

    recent_count = len(
        recent_live_alerts
    )


    if recent_count > 0:

        if recent_critical_count > 0:

            st.error(
                f"🚨 {recent_critical_count} critical "
                "network anomalies detected within "
                "the last 5 minutes."
            )

        elif recent_high_count > 0:

            st.error(
                f"⚠️ {recent_high_count} high-risk "
                "network anomalies detected within "
                "the last 5 minutes."
            )

        elif recent_medium_count > 0:

            st.warning(
                f"⚠️ {recent_medium_count} medium-risk "
                "network anomalies detected within "
                "the last 5 minutes."
            )

    else:

        st.success(
            "✅ No network anomalies detected "
            "within the last 5 minutes."
        )


    # =====================================================
    # RECENT LIVE ANOMALIES
    # =====================================================

    st.divider()

    st.subheader(
        "🚨 Recent Live Network Anomalies"
    )


    if len(recent_live_alerts) > 0:

        live_columns = [
            "id",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "packet_count",
            "total_bytes",
            "duration",
            "packets_per_second",
            "bytes_per_second",
            "average_packet_size",
            "severity",
            "detected_at",
            "status"
        ]


        available_live_columns = [
            column
            for column in live_columns
            if column in recent_live_alerts.columns
        ]


        ui.table(
            recent_live_alerts[
                available_live_columns
            ],
            use_container_width=True,
            hide_index=True
        )


        # =================================================
        # GEOIP WORLD MAP (UPGRADE — Tier 2)
        # =================================================
        # NOTE: most src_ip values captured on a college/home network
        # will be private/LAN addresses with no real-world location —
        # geoip_lookup.py labels those "Internal Network" instead of
        # sending them to the API, and this map only plots IPs that
        # actually resolved to a real lat/lon.

        with st.expander("🌍 Source IP Geolocation Map", expanded=False):

            unique_ips = (
                recent_live_alerts["src_ip"]
                .dropna()
                .unique()
                .tolist()
            )

            if len(unique_ips) == 0:

                st.info("No source IPs available to map.")

            else:

                with st.spinner(
                    f"Resolving {len(unique_ips)} source IP(s)..."
                ):

                    geo_results = lookup_many(unique_ips)

                mappable = [
                    r for r in geo_results
                    if r["status"] == "success" and r["lat"] is not None
                ]

                internal_count = len(
                    [r for r in geo_results if r["status"] == "private"]
                )

                if internal_count > 0:

                    st.caption(
                        f"ℹ️ {internal_count} of {len(unique_ips)} source "
                        "IP(s) are internal/private network addresses "
                        "and have no real-world location — not plotted."
                    )

                if len(mappable) == 0:

                    st.info(
                        "No public/geolocatable source IPs in this batch."
                    )

                else:

                    geo_df = pd.DataFrame(mappable)

                    fig = px.scatter_geo(
                        geo_df,
                        lat="lat",
                        lon="lon",
                        hover_name="ip",
                        hover_data=["country", "city", "isp"],
                        projection="natural earth",
                        title="Source IP Origins"
                    )

                    ui.plotly_chart(fig, use_container_width=True)

                    ui.table(
                        geo_df[["ip", "country", "city", "isp"]],
                        use_container_width=True,
                        hide_index=True
                    )

    else:

        st.success(
            "No recent live network anomalies detected."
        )


    # =====================================================
    # CRITICAL ALERTS
    # =====================================================

    st.divider()

    st.subheader(
        "🔥 Critical Alerts"
    )


    if len(critical_alerts) > 0:

        ui.table(
            critical_alerts.head(10),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No critical alerts detected."
        )


    # =====================================================
    # ALL ALERTS
    # =====================================================

    st.divider()

    st.subheader(
        "📋 All Alerts"
    )


    attack_filter = st.selectbox(
        "Filter By Attack Type",
        [
            "All",
            "DoS",
            "Probe",
            "R2L",
            "U2R",
            "Live Anomaly"
        ]
    )


    if attack_filter == "All":

        filtered_df = all_alerts

    else:

        filtered_df = all_alerts[
            all_alerts["attack_type"]
            == attack_filter
        ]


    ui.table(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# DATASET ATTACKS PAGE
# =========================================================

elif page == "Dataset Attacks":

    ui.page_header(
        "🤖 Dataset Attack Classification",
        ("Attacks classified by the NSL-KDD "
        "Random Forest model.")
    )


    col1, col2 = st.columns(2)


    with col1:

        st.metric(
            "Dataset Alerts",
            len(dataset_alerts)
        )


    with col2:

        dataset_critical = len(
            dataset_alerts[
                dataset_alerts["severity"]
                == "Critical"
            ]
        )

        st.metric(
            "Critical Dataset Alerts",
            dataset_critical
        )


    st.divider()


    dataset_filter = st.selectbox(
        "Select Attack Category",
        [
            "All",
            "DoS",
            "Probe",
            "R2L",
            "U2R"
        ]
    )


    if dataset_filter == "All":

        dataset_filtered = dataset_alerts

    else:

        dataset_filtered = dataset_alerts[
            dataset_alerts["attack_type"]
            == dataset_filter
        ]


    ui.table(
        dataset_filtered,
        use_container_width=True,
        hide_index=True
    )


    st.divider()


    if len(dataset_alerts) > 0:

        dataset_counts = (
            dataset_alerts["attack_type"]
            .value_counts()
            .reset_index()
        )


        dataset_counts.columns = [
            "Attack Type",
            "Count"
        ]

        # Added template='plotly_dark'
        fig_dataset = px.bar(
            dataset_counts,
            x="Attack Type",
            y="Count",
            title="Dataset Attack Classification",
            template="plotly_white",
            color="Attack Type"
        )


        ui.plotly_chart(
            fig_dataset,
            use_container_width=True
        )


# =========================================================
# LIVE ANOMALIES PAGE
# =========================================================

elif page == "Live Anomalies":

    ui.page_header(
        "🌐 Live Network Anomaly Detection",
        ("Live network flows analysed using "
        "the Isolation Forest anomaly detection model.")
    )


    col1, col2 = st.columns(2)


    with col1:

        st.metric(
            "Total Live Anomalies",
            len(live_alerts)
        )


    with col2:

        st.metric(
            "Recent Anomalies",
            len(recent_live_alerts)
        )


    st.divider()


    if len(live_alerts) > 0:

        st.error(
            f"{len(live_alerts)} live network "
            "anomalies stored in the alert database."
        )


        ui.table(
            live_alerts,
            use_container_width=True,
            hide_index=True
        )


    else:

        st.success(
            "No live network anomalies detected."
        )


    st.divider()


    st.info(
        "A live anomaly represents unusual network "
        "behaviour compared with the learned normal "
        "baseline. It is not automatically a confirmed "
        "cyber attack."
    )


# =========================================================
# RESPONSE CENTER PAGE
# =========================================================

elif page == "Response Center":

    ui.page_header(
        "🚨 NIDRS Response Center",
        ("Investigate alerts and manage "
        "incident response workflow.")
    )


    # =====================================================
    # RESPONSE METRICS
    # =====================================================

    new_alert_count = len(
        all_alerts[
            all_alerts["status"] == "New"
        ]
    )

    investigating_count = len(
        all_alerts[
            all_alerts["status"] == "Investigating"
        ]
    )

    resolved_count = len(
        all_alerts[
            all_alerts["status"] == "Resolved"
        ]
    )

    false_positive_count = len(
        all_alerts[
            all_alerts["status"] == "False Positive"
        ]
    )


    col1, col2, col3, col4 = st.columns(4)


    with col1:

        st.metric(
            "🆕 New Alerts",
            new_alert_count
        )


    with col2:

        st.metric(
            "🔎 Investigating",
            investigating_count
        )


    with col3:

        st.metric(
            "✅ Resolved",
            resolved_count
        )


    with col4:

        st.metric(
            "⚪ False Positive",
            false_positive_count
        )


    st.divider()


    # =====================================================
    # ALERT SELECTION
    # =====================================================

    st.subheader(
        "🔍 Select Alert"
    )


    alert_options = all_alerts[
        "id"
    ].tolist()


    if len(alert_options) > 0:

        selected_alert_id = st.selectbox(
            "Select Alert ID",
            alert_options
        )


        selected_alert = all_alerts[
            all_alerts["id"]
            == selected_alert_id
        ].iloc[0]


        st.divider()


        # =================================================
        # ALERT DETAILS
        # =================================================

        st.subheader(
            "📋 Alert Details"
        )


        col1, col2, col3 = st.columns(3)


        with col1:

            st.metric(
                "Alert ID",
                selected_alert["id"]
            )

            st.write(
                "**Attack Type:**",
                selected_alert["attack_type"]
            )


        with col2:

            st.metric(
                "Severity",
                selected_alert["severity"]
            )

            st.write(
                "**Current Status:**",
                selected_alert["status"]
            )


        with col3:

            st.write(
                "**Detected At:**"
            )

            st.write(
                selected_alert["detected_at"]
            )

            st.write(
                "**Response At:**"
            )

            st.write(
                selected_alert["response_at"]
            )


        # =================================================
        # NETWORK FLOW DETAILS
        # =================================================

        if (
            selected_alert["attack_type"]
            == "Live Anomaly"
        ):

            st.divider()

            st.subheader(
                "🌐 Network Flow Details"
            )


            col1, col2 = st.columns(2)


            with col1:

                st.write(
                    "**Source IP:**",
                    selected_alert["src_ip"]
                )

                st.write(
                    "**Source Port:**",
                    selected_alert["src_port"]
                )

                st.write(
                    "**Protocol:**",
                    selected_alert["protocol"]
                )

                st.write(
                    "**Packet Count:**",
                    selected_alert["packet_count"]
                )

                st.write(
                    "**Packets / Second:**",
                    selected_alert[
                        "packets_per_second"
                    ]
                )


            with col2:

                st.write(
                    "**Destination IP:**",
                    selected_alert["dst_ip"]
                )

                st.write(
                    "**Destination Port:**",
                    selected_alert["dst_port"]
                )

                st.write(
                    "**Total Bytes:**",
                    selected_alert["total_bytes"]
                )

                st.write(
                    "**Duration:**",
                    selected_alert["duration"]
                )

                st.write(
                    "**Bytes / Second:**",
                    selected_alert[
                        "bytes_per_second"
                    ]
                )


            # =============================================
            # THREAT INTELLIGENCE LOOKUP (UPGRADE — Tier 2)
            # =============================================

            st.divider()

            st.subheader("🕵️ Threat Intelligence")

            # ---- automatic enrichment stored with the alert -------------
            # (written by response/enrichment.py when the alert was created)
            _stored_ip = selected_alert.get("enriched_ip")
            _stored_status = selected_alert.get("intel_status")

            if _stored_status is not None and not pd.isna(_stored_status):

                _geo_city = selected_alert.get("geo_city")
                _geo_country = selected_alert.get("geo_country")
                _abuse = selected_alert.get("abuse_score")
                _reports = selected_alert.get("abuse_reports")

                _location = ", ".join(
                    str(x) for x in (_geo_city, _geo_country)
                    if x is not None and not pd.isna(x)
                ) or "Not available"

                st.markdown("**Automatic enrichment (stored with this alert)**")

                ae1, ae2, ae3 = st.columns(3)

                with ae1:
                    st.write("**External IP**")
                    st.write(
                        _stored_ip
                        if _stored_ip is not None and not pd.isna(_stored_ip)
                        else "None (internal traffic)"
                    )

                with ae2:
                    st.write("**GeoIP Location**")
                    st.write(_location)

                with ae3:
                    st.write("**AbuseIPDB Score**")
                    st.write(
                        f"{int(_abuse)}% ({int(_reports)} reports)"
                        if _abuse is not None and not pd.isna(_abuse)
                        else "Not available"
                    )

                st.caption(f"Lookup status: {_stored_status}")

                _mitre_t = selected_alert.get("mitre_technique")

                if _mitre_t is not None and not pd.isna(_mitre_t):
                    st.write(
                        f"**MITRE ATT&CK:** {_mitre_t} "
                        f"({selected_alert.get('mitre_tactic')})"
                    )

                st.divider()

            else:

                st.caption(
                    "This alert has not been enriched yet. Run "
                    "`python response/enrichment.py --backfill` to enrich "
                    "stored alerts, or use the manual check below."
                )

            src_ip_val = selected_alert.get("src_ip")

            if pd.isna(src_ip_val) or not src_ip_val:

                st.info("No source IP available to check.")

            elif st.button(
                f"Re-check reputation of {src_ip_val}",
                key=f"threat_intel_{selected_alert['id']}"
            ):

                with st.spinner("Querying AbuseIPDB..."):
                    intel = check_ip_reputation(src_ip_val)

                if intel["status"] == "private":

                    st.info(
                        f"{src_ip_val} is an internal/private network "
                        "address — no external threat intel available."
                    )

                elif intel["status"] == "no_api_key":

                    st.warning(
                        "NIDRS_ABUSEIPDB_KEY environment variable is not "
                        "set. Get a free key at "
                        "https://www.abuseipdb.com/account/api and set "
                        "it as an environment variable to enable this."
                    )

                elif intel["status"] == "fail":

                    st.error(
                        "Could not reach AbuseIPDB (check internet "
                        "connection / API key)."
                    )

                else:

                    ti_col1, ti_col2, ti_col3 = st.columns(3)

                    with ti_col1:
                        st.metric(
                            "Abuse Confidence",
                            f"{intel['abuse_score']}%"
                        )

                    with ti_col2:
                        st.metric(
                            "Total Reports",
                            intel["total_reports"]
                        )

                    with ti_col3:
                        st.write("**Risk Level**")
                        st.write(risk_label(intel["abuse_score"]))

                    if intel["is_whitelisted"]:
                        st.success(
                            "This IP is on AbuseIPDB's whitelist "
                            "(known-good, e.g. major public DNS/CDN)."
                        )


        # =================================================
        # AUTOMATED RESPONSE RECOMMENDATION
        # =================================================

        st.divider()

        st.subheader(
            "🤖 Automated Response Recommendation"
        )


        recommendation = (
            generate_response_recommendation(
                selected_alert
            )
        )


        col1, col2 = st.columns(2)


        with col1:

            st.metric(
                "Risk Level",
                recommendation[
                    "risk_level"
                ]
            )


        with col2:

            st.write(
                "**Recommended Action:**"
            )

            st.warning(
                recommendation[
                    "recommended_action"
                ]
            )


        st.write(
            "**Reason:**"
        )

        st.info(
            recommendation[
                "reason"
            ]
        )


        st.write(
            "**Suggested Responses:**"
        )


        for response in recommendation[
            "suggested_responses"
        ]:

            st.write(
                f"• {response}"
            )


        # =================================================
        # MITRE ATT&CK MAPPING (UPGRADE — Tier 2)
        # =================================================

        mitre_info = recommendation.get("mitre_attack")

        if mitre_info:

            st.write("**MITRE ATT&CK Mapping:**")

            mitre_col1, mitre_col2 = st.columns(2)

            with mitre_col1:
                st.write(
                    f"🎯 **{mitre_info['technique_id']}** — "
                    f"{mitre_info['technique_name']}"
                )
                st.caption(f"Tactic: {mitre_info['tactic']}")

            with mitre_col2:
                st.markdown(
                    f"[View on attack.mitre.org]({mitre_info['url']})"
                )

            st.caption(mitre_info["description"])


        # =================================================
        # INCIDENT RESPONSE
        # =================================================

        st.divider()

        st.subheader(
            "🛡️ Incident Response"
        )


        status_options = [
            "New",
            "Investigating",
            "Resolved",
            "False Positive"
        ]


        current_status = selected_alert["status"]

        if current_status not in status_options:

            current_status = "New"


        selected_status = st.selectbox(
            "Alert Status",
            status_options,
            index=status_options.index(
                current_status
            )
        )


        old_response_action = (
            selected_alert["response_action"]
        )


        if pd.isna(old_response_action):

            old_response_action = ""


        response_action = st.text_area(
            "Response Action / Analyst Notes",
            value=old_response_action,
            placeholder=(
                "Example: Investigated network flow. "
                "Source IP behaviour reviewed."
            )
        )


        update_response = st.button(
            "🛡️ Update Alert Response",
            type="primary",
            use_container_width=True
        )


        if update_response:

            if (
                selected_status != "New"
                and response_action.strip() == ""
            ):

                st.warning(
                    "Please enter response action "
                    "or analyst notes."
                )


            else:

                try:

                    update_alert_response(
                        selected_alert_id,
                        selected_status,
                        response_action.strip()
                    )


                    st.success(
                        f"Alert {selected_alert_id} "
                        "response updated successfully."
                    )


                    st.rerun()


                except Exception as error:

                    st.error(
                        f"Response Update Error: {error}"
                    )


        # =================================================
        # PREVIOUS RESPONSE
        # =================================================

        if (
            not pd.isna(
                selected_alert["response_action"]
            )
        ):

            st.divider()

            st.subheader(
                "📝 Saved Response"
            )

            st.info(
                selected_alert[
                    "response_action"
                ]
            )
         # =================================================
        # PDF INCIDENT REPORT
        # =================================================

        st.divider()

        st.subheader(
            "📄 Incident Report"
        )

        # FIX: was a relative path "reports/Incident_....pdf" with no
        # folder creation — this only worked if Streamlit happened to be
        # launched from inside dashboard/ AND a "reports" folder already
        # existed there. The auto-generated report on the Dashboard page
        # (for critical live alerts) already used the robust BASE_DIR-based
        # path + mkdir; this button now does the same.
        report_dir = BASE_DIR / "reports"
        report_dir.mkdir(exist_ok=True)

        report_path = str(
            report_dir / f"Incident_{selected_alert['id']}.pdf"
        )

        if st.button(
            "📄 Generate Incident Report"
        ):

            try:

                create_incident_report(
                    selected_alert,
                    report_path
                )

                st.success(
                    "Incident Report Generated Successfully."
                )

                with open(
                    report_path,
                    "rb"
                ) as pdf_file:

                    st.download_button(
                        label="⬇ Download PDF Report",
                        data=pdf_file,
                        file_name=f"Incident_{selected_alert['id']}.pdf",
                        mime="application/pdf"
                    )

            except Exception as error:

                st.error(
                    f"PDF Generation Error: {error}"
                )


    else:

        st.info(
            "No alerts available for incident response."
        )

# =========================================================
# RESPONSE HISTORY
# =========================================================
# FIX: "Response History" was listed as a selectable page in the sidebar
# dropdown (line ~304), but there was NO "elif page == 'Response History':"
# block anywhere — the if/elif chain jumped straight from Response Center
# to System Architecture. Selecting it rendered a completely blank page
# (nothing matched, so nothing ran). This adds the missing page.

elif page == "Response History":

    ui.page_header(
        "🕘 Response History",
        ("A log of every alert an analyst has already acted on "
        "(status changed away from 'New').")
    )

    history = all_alerts[
        all_alerts["status"] != "New"
    ].copy()

    if len(history) == 0:

        st.info(
            "No response history yet — alerts will appear here once "
            "their status is updated from the Response Center."
        )

    else:

        history = history.sort_values(
            by="response_at",
            ascending=False,
            na_position="last"
        )

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Investigating",
                len(history[history["status"] == "Investigating"])
            )

        with col2:
            st.metric(
                "Resolved",
                len(history[history["status"] == "Resolved"])
            )

        with col3:
            st.metric(
                "False Positive",
                len(history[history["status"] == "False Positive"])
            )

        st.divider()

        status_filter = st.multiselect(
            "Filter by status",
            options=sorted(history["status"].dropna().unique().tolist()),
            default=sorted(history["status"].dropna().unique().tolist())
        )

        filtered_history = history[
            history["status"].isin(status_filter)
        ]

        display_columns = [
            col for col in [
                "id",
                "attack_type",
                "severity",
                "status",
                "response_action",
                "response_at",
                "detected_at",
                "src_ip",
                "dst_ip"
            ]
            if col in filtered_history.columns
        ]

        ui.table(
            filtered_history[display_columns],
            use_container_width=True,
            hide_index=True
        )



elif page == "System Architecture":

    ui.page_header(
        "🏗️ NIDRS System Architecture",
        ("""
This page explains how the complete AI Powered
Network Intrusion Detection and Response System works.
""")
    )

    st.divider()

    st.subheader("📌 Overall Workflow")

    st.markdown("""            NSL-KDD Dataset
                   │
                   ▼
        Data Preprocessing
                   │
                   ▼
  Random Forest Attack Classifier
                   │
                   ▼
         Dataset Alerts Stored
                   │
                   ▼
           SQLite Database
                   ▲
                   │Live Network Packets → Feature Extraction
│
▼
Isolation Forest Detection
│
▼
Live Anomaly Alerts
│
▼
Response Recommendation
│
▼
Analyst Investigation
│
▼
Incident Response Update
│
▼
PDF Incident Report

""")
    st.divider()

    st.subheader("🧠 AI Models Used")

    model_df = pd.DataFrame({

        "Model":[
            "Random Forest",
            "Isolation Forest"
        ],

        "Purpose":[
            "Dataset Attack Classification",
            "Live Network Anomaly Detection"
        ],

        "Input":[
            "NSL-KDD Features",
            "Captured Network Flow"
        ],

        "Output":[
            "Attack Type",
            "Normal / Anomaly"
        ]
    })

    ui.table(
        model_df,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    st.subheader("⚙️ Technologies Used")

    tech_df = pd.DataFrame({

        "Technology":[
            "Python",
            "Streamlit",
            "Scikit-Learn",
            "SQLite",
            "Pandas",
            "Plotly",
            "Scapy",
            "ReportLab"
        ],

        "Purpose":[
            "Programming",
            "Dashboard",
            "Machine Learning",
            "Database",
            "Data Processing",
            "Visualization",
            "Packet Capture",
            "PDF Report Generation"
        ]
    })

    ui.table(
        tech_df,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    st.success("✔ Complete AI Detection → Response → Reporting Workflow")

# =========================================================
# ANALYTICS PAGE
# =========================================================

elif page == "📈 Analytics":

    ui.page_header(
        "📈 Security Analytics Dashboard",
        ("Overall security analytics generated from "
        "dataset attacks and live network anomalies.")
    )

    st.divider()
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
        "Total Alerts",
        len(all_alerts)
    )

    with col2:
        st.metric(
        "Dataset Alerts",
        len(dataset_alerts)
    )

    with col3:
        st.metric(
        "Live Anomalies",
        len(live_alerts)
    )

    with col4:
        critical = len(
            all_alerts[
                all_alerts["severity"] == "Critical"
            ]
        )

        # FIX: st.metric() call was outside the "with col4:" block
        # (wrong indentation), so it rendered below the whole row of
        # columns instead of inside the 4th column, breaking the layout.
        st.metric(
            "Critical Alerts",
            critical
        )

    st.divider()
    st.subheader("🎯 Attack Distribution")

    attack_counts = (
    all_alerts["attack_type"]
    .value_counts()
    .reset_index()
    )

    attack_counts.columns = [
    "Attack Type",
    "Count"
    ]

    # Added template='plotly_dark'
    fig_attack = px.pie(
    attack_counts,
    values="Count",
    names="Attack Type",
    hole=0.45,
    title="Attack Distribution",
    template="plotly_white"
    )

    ui.plotly_chart(
    fig_attack,
    use_container_width=True
    )

    st.divider()
    st.subheader("📊 Severity Distribution")

    severity_counts = (
    all_alerts["severity"]
    .value_counts()
    .reset_index()
    )

    severity_counts.columns = [
    "Severity",
    "Count"
    ]

    # Added template='plotly_dark'
    fig_sev = px.bar(
    severity_counts,
    x="Severity",
    y="Count",
    text="Count",
    color="Severity",
    title="Severity Distribution",
    template="plotly_white",
    color_discrete_map={
        "Critical": "#ef4444", 
        "High": "#f97316", 
        "Medium": "#eab308", 
        "Low": "#3b82f6"
    }
    )

    fig_sev.update_traces(
    textposition="outside"
    )

    ui.plotly_chart(
    fig_sev,
    use_container_width=True
    )

    st.divider()
    st.subheader("⚖️ Live vs Dataset Alerts")

    comparison = pd.DataFrame({
    "Category": [
        "Dataset Alerts",
        "Live Anomalies"
    ],
    "Count": [
        len(dataset_alerts),
        len(live_alerts)
    ]
    })

    # Added template='plotly_dark'
    fig_comp = px.bar(
    comparison,
    x="Category",
    y="Count",
    color="Category",
    text="Count",
    title="Dataset vs Live Alerts",
    template="plotly_white"
    )

    fig_comp.update_traces(
    textposition="outside"
    )

    ui.plotly_chart(
    fig_comp,
    use_container_width=True
    )

    st.divider() 
    st.divider()

    st.subheader("🌍 Top Source IP Addresses")

    live_ip_data = live_alerts.copy()

    if (
    len(live_ip_data) > 0
    and "src_ip" in live_ip_data.columns
    ):

        top_sources = (
        live_ip_data["src_ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )

        top_sources.columns = [
        "Source IP",
        "Alerts"
    ]

        # Added template='plotly_dark'
        fig_src = px.bar(
        top_sources,
        x="Source IP",
        y="Alerts",
        text="Alerts",
        color="Alerts",
        title="Top Source IP Addresses",
        template="plotly_white",
        color_continuous_scale="Reds"
    )

        fig_src.update_traces(
        textposition="outside"
    )

        ui.plotly_chart(
        fig_src,
        use_container_width=True
    )

    else:

        st.info("No live source IP data available.")
    st.divider()

    st.subheader("🎯 Top Destination IP Addresses")

    if (
    len(live_ip_data) > 0
    and "dst_ip" in live_ip_data.columns
    ):

        top_dest = (
        live_ip_data["dst_ip"]
        .value_counts()
        .head(10)
        .reset_index()
        )

        top_dest.columns = [
        "Destination IP",
        "Alerts"
        ]

        # Added template='plotly_dark'
        fig_dst = px.bar(
        top_dest,
        x="Destination IP",
        y="Alerts",
        text="Alerts",
        color="Alerts",
        title="Top Destination IP Addresses",
        template="plotly_white",
        color_continuous_scale="Reds"
        )

        fig_dst.update_traces(
        textposition="outside"
        )

        ui.plotly_chart(
        fig_dst,
        use_container_width=True
        )

    else:

        st.info("No destination IP data available.")
    # =====================================================
# ALERT TIMELINE
# =====================================================

    st.divider()

    st.subheader("📈 Alert Timeline")

    timeline = all_alerts.copy()

    if (
    len(timeline) > 0
    and "detected_at" in timeline.columns
)   :

        timeline["detected_at"] = pd.to_datetime(
        timeline["detected_at"],
        errors="coerce"
        )

        timeline = timeline.dropna(
        subset=["detected_at"]
        )

        timeline["Time"] = (
        timeline["detected_at"]
        .dt.strftime("%H:%M")
        )

        timeline_counts = (
        timeline.groupby("Time")
        .size()
        .reset_index(name="Alerts")
        )

        # Added template='plotly_dark'
        fig_time = px.line(
        timeline_counts,
        x="Time",
        y="Alerts",
        markers=True,
        title="Alert Detection Timeline",
        template="plotly_white"
        )

        fig_time.update_traces(
        line=dict(width=3, color="#1769aa")
        )

        ui.plotly_chart(
        fig_time,
        use_container_width=True
        )

    else:  

        st.info(
        "No alert timeline data available."
        )
    

# =========================================================
# LOGS PAGE
# =========================================================

elif page == "Logs":

    ui.page_header("📜 System Logs")

    ui.table(
        all_alerts,
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# SETTINGS PAGE
# =========================================================

elif page == "Settings":

    ui.page_header("⚙️ Settings")

    st.subheader(
        "NIDRS System Configuration"
    )

    st.write(
        "Offline Model: Random Forest"
    )

    st.write(
        "Live Model: Isolation Forest"
    )

    st.write(
        "Dataset Features: 41"
    )

    st.write(
        "Live Flow Features: 6"
    )

    st.write(
        "Live Capture Size: 500 Packets"
    )

    st.write(
        "Threat Analysis Window: 5 Minutes"
    )

    st.write(
        "Threat Engine: Severity-Aware"
    )

    st.write(
        "Response Engine: Automated Recommendation + Analyst Workflow"
    )

    st.write(
        "System Status: ONLINE"
    )