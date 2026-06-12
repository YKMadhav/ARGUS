import html
import json
import os
import random
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st


st.set_page_config(
    page_title="ARGUS // Investigation Console",
    page_icon="ARGUS",
    layout="wide",
    initial_sidebar_state="collapsed",
)

LOG_FILE = "./logs/alerts.json"


def load_alerts():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            data = json.load(f)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []


def safe(value, default="N/A"):
    if value is None or value == "":
        return default
    return html.escape(str(value))


def number(value):
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def pct(part, whole):
    if not whole:
        return "0.0%"
    return f"{(part / whole) * 100:.1f}%"


def action_for(alert):
    blocked = alert.get("blocked", alert.get("threat_level") == "CRITICAL")
    return "BLOCKED" if blocked else "MONITORED"


def severity_weight(level):
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(level).upper(), 1)


def render_binary_background(token_count=54):
    tokens = []
    for _ in range(token_count):
        bits = "".join(random.choice("01") for _ in range(random.randint(10, 26)))
        grouped_bits = " ".join(bits[i:i + 4] for i in range(0, len(bits), 4))
        x = random.uniform(-8, 98)
        y = random.uniform(-12, 108)
        dx = random.uniform(-180, 180)
        dy = random.uniform(-180, 180)
        rot = random.uniform(-28, 28)
        rot_end = rot + random.uniform(-18, 18)
        duration = random.uniform(11, 28)
        delay = random.uniform(-28, 0)
        size = random.uniform(9, 16)
        alpha = random.uniform(0.08, 0.24)
        tokens.append(
            f"""
<span class="binary-token" style="
  --x:{x:.2f}vw; --y:{y:.2f}vh;
  --dx:{dx:.2f}px; --dy:{dy:.2f}px;
  --rot:{rot:.2f}deg; --rot-end:{rot_end:.2f}deg;
  --dur:{duration:.2f}s; --delay:{delay:.2f}s;
  --size:{size:.2f}px; --alpha:{alpha:.3f};
">{grouped_bits}</span>
"""
        )

    st.markdown(
        f'<div class="binary-rain">{"".join(tokens)}</div>',
        unsafe_allow_html=True,
    )


def render_stat(label, value, detail, tone="lime"):
    st.markdown(
        f"""
<div class="stat stat-{tone}">
  <div class="stat-label">{safe(label)}</div>
  <div class="stat-value">{safe(value)}</div>
  <div class="stat-detail">{safe(detail)}</div>
</div>
""",
        unsafe_allow_html=True,
    )


def render_empty_state():
    st.markdown(
        """
<div class="empty-state">
  <div class="empty-title">NO ACTIVE INCIDENTS</div>
  <div class="empty-copy">Sensor feed is online. Waiting for confirmed anomaly evidence.</div>
</div>
""",
        unsafe_allow_html=True,
    )


st.markdown(
    """
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

  :root {
    --bg: #050806;
    --panel: #09110c;
    --panel-2: #0d1710;
    --line: #213020;
    --line-hot: #20C20E;
    --lime: #20C20E;
    --radium: #20C20E;
    --mint: #20C20E;
    --cyan: #43e6ff;
    --amber: #ffb84a;
    --red: #ff4d5e;
    --text: #e8ffe0;
    --muted: #88a486;
    --dim: #4d624d;
  }

  html, body, [data-testid="stAppViewContainer"] {
    background:
      linear-gradient(180deg, rgba(32,194,14,0.055) 0%, rgba(5,8,6,0) 190px),
      radial-gradient(circle at 75% 0%, rgba(67,230,255,0.10), transparent 32%),
      #050806 !important;
    color: var(--text) !important;
    font-family: Inter, sans-serif !important;
  }

  [data-testid="stAppViewContainer"]::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background-image:
      linear-gradient(rgba(32,194,14,0.035) 1px, transparent 1px),
      linear-gradient(90deg, rgba(32,194,14,0.028) 1px, transparent 1px);
    background-size: 44px 44px;
    mask-image: linear-gradient(to bottom, black, transparent 72%);
  }

  .binary-rain {
    position: fixed;
    inset: 0;
    pointer-events: none;
    overflow: hidden;
    z-index: 0;
  }

  .binary-token {
    position: absolute;
    left: var(--x);
    top: var(--y);
    color: rgba(32,194,14,var(--alpha));
    font-family: "JetBrains Mono", monospace;
    font-size: var(--size);
    line-height: 1;
    letter-spacing: 0.14em;
    white-space: nowrap;
    text-shadow: 0 0 10px rgba(32,194,14,0.28);
    transform: translate3d(0, 0, 0) rotate(var(--rot));
    animation: binaryFloat var(--dur) linear infinite;
    animation-delay: var(--delay);
    opacity: 0;
  }

  @keyframes binaryFloat {
    0% {
      transform: translate3d(0, 0, 0) rotate(var(--rot));
      opacity: 0;
    }
    12% { opacity: var(--alpha); }
    62% { opacity: var(--alpha); }
    100% {
      transform: translate3d(var(--dx), var(--dy), 0) rotate(var(--rot-end));
      opacity: 0;
    }
  }

  @keyframes hoverScan {
    0% { transform: translateX(-120%); opacity: 0; }
    20% { opacity: 0.72; }
    100% { transform: translateX(120%); opacity: 0; }
  }

  .main .block-container {
    max-width: 1500px;
    padding-top: 28px;
    padding-bottom: 22px;
    position: relative;
    z-index: 1;
  }

  [data-testid="stHeader"] {
    background: rgba(5,8,6,0.86) !important;
    backdrop-filter: blur(12px);
  }

  h1, h2, h3, [data-testid="stMarkdownContainer"] h2, [data-testid="stMarkdownContainer"] h3 {
    color: var(--text) !important;
    font-family: Inter, sans-serif !important;
    letter-spacing: 0 !important;
  }

  hr {
    border-color: rgba(32,194,14,0.22) !important;
    margin: 22px 0 !important;
  }

  .hero {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 24px;
    align-items: end;
    padding: 22px 0 16px;
    border-bottom: 1px solid rgba(32,194,14,0.24);
  }

  .eyebrow {
    color: var(--radium);
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .brand {
    display: flex;
    align-items: baseline;
    gap: 14px;
    flex-wrap: wrap;
  }

  .brand-title {
    color: var(--lime);
    font-size: clamp(34px, 5vw, 66px);
    font-weight: 800;
    line-height: 0.95;
    text-shadow: 0 0 24px rgba(32,194,14,0.34);
  }

  .brand-subtitle {
    color: var(--muted);
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .status-strip {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  .chip {
    border: 1px solid rgba(32,194,14,0.34);
    background: rgba(12,23,16,0.82);
    color: var(--text);
    border-radius: 8px;
    padding: 8px 10px;
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    white-space: nowrap;
  }

  .chip strong {
    color: var(--lime);
  }

  .section-title {
    color: var(--lime);
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin: 8px 0 12px;
  }

  .stat {
    min-height: 122px;
    border: 1px solid rgba(32,194,14,0.22);
    border-radius: 8px;
    background: linear-gradient(180deg, rgba(32,194,14,0.055), rgba(9,17,12,0.92));
    padding: 16px;
    position: relative;
    overflow: hidden;
    transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease, background 180ms ease;
  }

  .stat::before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    width: 4px;
    height: 100%;
    background: var(--lime);
    box-shadow: 0 0 18px rgba(32,194,14,0.7);
  }

  .stat::after,
  .incident::after,
  .snapshot-card::after {
    content: "";
    position: absolute;
    inset: 0;
    pointer-events: none;
    background: linear-gradient(105deg, transparent 0%, rgba(32,194,14,0.16) 50%, transparent 100%);
    transform: translateX(-120%);
    opacity: 0;
  }

  .stat:hover,
  .incident:hover,
  .snapshot-card:hover {
    transform: translateY(-3px);
    border-color: rgba(32,194,14,0.62);
    box-shadow: 0 0 0 1px rgba(32,194,14,0.16), 0 16px 44px rgba(32,194,14,0.11);
    background: linear-gradient(180deg, rgba(32,194,14,0.095), rgba(9,17,12,0.95));
  }

  .stat:hover::after,
  .incident:hover::after,
  .snapshot-card:hover::after {
    animation: hoverScan 900ms ease-out;
  }

  .stat-red::before { background: var(--red); box-shadow: 0 0 18px rgba(255,77,94,0.58); }
  .stat-amber::before { background: var(--amber); box-shadow: 0 0 18px rgba(255,184,74,0.5); }
  .stat-cyan::before { background: var(--cyan); box-shadow: 0 0 18px rgba(67,230,255,0.5); }

  .stat-label {
    color: var(--muted);
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 14px;
  }

  .stat-value {
    color: var(--text);
    font-size: 30px;
    font-weight: 800;
    line-height: 1;
  }

  .stat-detail {
    color: var(--dim);
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    margin-top: 12px;
  }

  .incident {
    border: 1px solid rgba(32,194,14,0.20);
    border-radius: 8px;
    background: rgba(9,17,12,0.78);
    padding: 13px 14px;
    margin-bottom: 10px;
    position: relative;
    overflow: hidden;
    transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease, background 180ms ease;
  }

  .incident-critical {
    border-color: rgba(255,77,94,0.44);
    background: linear-gradient(90deg, rgba(255,77,94,0.13), rgba(9,17,12,0.82));
  }

  .incident-high {
    border-color: rgba(255,184,74,0.36);
    background: linear-gradient(90deg, rgba(255,184,74,0.11), rgba(9,17,12,0.82));
  }

  .incident-head {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 9px;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 3px 9px;
    font-family: "JetBrains Mono", monospace;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .badge-critical { background: rgba(255,77,94,0.18); color: #ff8d99; border: 1px solid rgba(255,77,94,0.45); }
  .badge-high { background: rgba(255,184,74,0.15); color: #ffd494; border: 1px solid rgba(255,184,74,0.42); }
  .badge-action { background: rgba(32,194,14,0.13); color: var(--lime); border: 1px solid rgba(32,194,14,0.28); }
  .badge-watch { background: rgba(67,230,255,0.12); color: #9cf3ff; border: 1px solid rgba(67,230,255,0.34); }

  .ip {
    color: var(--lime);
    font-family: "JetBrains Mono", monospace;
    font-weight: 800;
  }

  .incident-type {
    color: var(--text);
    font-weight: 700;
  }

  .incident-time {
    color: var(--dim);
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    margin-left: auto;
  }

  .evidence-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 8px;
  }

  .evidence {
    background: rgba(32,194,14,0.045);
    border: 1px solid rgba(32,194,14,0.13);
    border-radius: 6px;
    padding: 8px;
  }

  .evidence span {
    display: block;
    color: var(--dim);
    font-family: "JetBrains Mono", monospace;
    font-size: 10px;
    text-transform: uppercase;
  }

  .evidence strong {
    color: var(--text);
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
  }

  .empty-state {
    border: 1px dashed rgba(32,194,14,0.35);
    border-radius: 8px;
    background: rgba(32,194,14,0.04);
    padding: 34px;
    text-align: center;
  }

  .empty-title {
    color: var(--lime);
    font-size: 18px;
    font-weight: 800;
    letter-spacing: 0.08em;
  }

  .empty-copy {
    color: var(--muted);
    margin-top: 8px;
  }

  .note {
    color: var(--muted);
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    margin-top: 8px;
  }

  .snapshot-card {
    border: 1px solid rgba(32,194,14,0.22);
    border-radius: 8px;
    background: rgba(9,17,12,0.78);
    padding: 14px;
    margin-bottom: 10px;
    position: relative;
    overflow: hidden;
    transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease, background 180ms ease;
  }

  .snapshot-label {
    color: var(--muted);
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 8px;
  }

  .snapshot-value {
    color: var(--lime);
    font-size: 26px;
    line-height: 1.08;
    font-weight: 800;
    overflow-wrap: anywhere;
  }

  .snapshot-detail {
    color: var(--dim);
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    margin-top: 8px;
  }

  [data-testid="stDataFrame"] {
    border: 1px solid rgba(32,194,14,0.22) !important;
    border-radius: 8px !important;
    overflow: hidden !important;
  }

  [data-testid="stMetric"] {
    background: rgba(9,17,12,0.76) !important;
    border: 1px solid rgba(32,194,14,0.22) !important;
    border-radius: 8px !important;
    padding: 14px !important;
  }

  [data-testid="stMetricLabel"] {
    color: var(--muted) !important;
    font-family: "JetBrains Mono", monospace !important;
  }

  [data-testid="stMetricValue"] {
    color: var(--lime) !important;
    font-weight: 800 !important;
  }

  @media (max-width: 900px) {
    .hero { grid-template-columns: 1fr; }
    .status-strip { justify-content: flex-start; }
    .evidence-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .incident-time { margin-left: 0; }
  }
</style>
""",
    unsafe_allow_html=True,
)


alerts = load_alerts()
df = pd.DataFrame(alerts)

if not df.empty:
    df = df.copy()
    df["threat_level"] = df.get("threat_level", "HIGH").fillna("HIGH").astype(str).str.upper()
    df["blocked"] = df.apply(lambda row: bool(row.get("blocked", row["threat_level"] == "CRITICAL")), axis=1)
    df["packets"] = pd.to_numeric(df.get("packets", 0), errors="coerce").fillna(0).astype(int)
    df["src_bytes"] = pd.to_numeric(df.get("src_bytes", 0), errors="coerce").fillna(0).astype(int)
    df["ports_hit"] = pd.to_numeric(df.get("ports_hit", 0), errors="coerce").fillna(0).astype(int)
    df["anomaly_score"] = pd.to_numeric(df.get("anomaly_score", 0), errors="coerce").fillna(0.0)
    df["streak"] = pd.to_numeric(df.get("streak", 0), errors="coerce").fillna(0).astype(int)
    df["severity"] = df["threat_level"].apply(severity_weight)
    df["event_id"] = [f"ARG-{i + 1:04d}" for i in range(len(df))]

total_alerts = len(alerts)
critical = int((df["threat_level"] == "CRITICAL").sum()) if not df.empty else 0
high = int((df["threat_level"] == "HIGH").sum()) if not df.empty else 0
unique_sources = int(df["ip"].nunique()) if not df.empty and "ip" in df else 0
blocked_ips = int(df.loc[df["blocked"], "ip"].nunique()) if not df.empty and "ip" in df else 0
total_packets = int(df["packets"].sum()) if not df.empty else 0
total_bytes = int(df["src_bytes"].sum()) if not df.empty else 0
max_ports = int(df["ports_hit"].max()) if not df.empty else 0
avg_score = float(df["anomaly_score"].mean()) if not df.empty else 0.0
latest_sync = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if total_alerts == 0:
    posture = "CLEAR"
elif critical:
    posture = "ACTIVE INCIDENT"
elif high:
    posture = "WATCHLIST"
else:
    posture = "OBSERVING"

render_binary_background()

st.markdown(
    f"""
<div class="hero">
  <div>
    <div class="eyebrow">ARGUS RADAR // INCIDENT INVESTIGATION MODE</div>
    <div class="brand">
      <div class="brand-title">ARGUS</div>
      <div class="brand-subtitle">Network Evidence Console</div>
    </div>
  </div>
  <div class="status-strip">
    <span class="chip">POSTURE <strong>{safe(posture)}</strong></span>
    <span class="chip">SENSOR <strong>ONLINE</strong></span>
    <span class="chip">SYNC <strong>{safe(latest_sync)}</strong></span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown('<div class="section-title">Command Overview</div>', unsafe_allow_html=True)
m1, m2, m3, m4, m5, m6 = st.columns(6)
with m1:
    render_stat("Total Alerts", number(total_alerts), f"{pct(critical, total_alerts)} critical", "lime")
with m2:
    render_stat("Critical", number(critical), f"{number(high)} high severity", "red" if critical else "lime")
with m3:
    render_stat("Sources", number(unique_sources), f"{number(blocked_ips)} blocked", "cyan")
with m4:
    render_stat("Packets", number(total_packets), "captured in alerts", "lime")
with m5:
    render_stat("Ports Peak", number(max_ports), "max unique ports", "amber" if max_ports else "lime")
with m6:
    render_stat("Avg Score", f"{avg_score:.4f}", f"{number(total_bytes)} bytes", "cyan")

st.divider()

if df.empty:
    render_empty_state()
else:
    latest = df.iloc[-1].to_dict()
    top_source = df["ip"].value_counts().idxmax()
    top_source_events = int(df["ip"].value_counts().max())
    top_attack = df["attack_type"].value_counts().idxmax() if "attack_type" in df else "N/A"

    a, b, c = st.columns([1.4, 1, 1])
    with a:
        st.markdown('<div class="section-title">Live Evidence Feed</div>', unsafe_allow_html=True)
        for alert in reversed(alerts[-10:]):
            threat = safe(str(alert.get("threat_level", "HIGH")).upper())
            is_critical = threat == "CRITICAL"
            action = action_for(alert)
            incident_class = "incident-critical" if is_critical else "incident-high"
            badge_class = "badge-critical" if is_critical else "badge-high"
            action_class = "badge-action" if action == "BLOCKED" else "badge-watch"
            st.markdown(
                f"""
<div class="incident {incident_class}">
  <div class="incident-head">
    <span class="badge {badge_class}">{threat}</span>
    <span class="badge {action_class}">{safe(action)}</span>
    <span class="ip">{safe(alert.get("ip"))}</span>
    <span class="incident-type">{safe(alert.get("attack_type"))}</span>
    <span class="incident-time">{safe(alert.get("timestamp"))}</span>
  </div>
  <div class="evidence-grid">
    <div class="evidence"><span>Packets</span><strong>{number(alert.get("packets", 0))}</strong></div>
    <div class="evidence"><span>Ports</span><strong>{number(alert.get("ports_hit", 0))}</strong></div>
    <div class="evidence"><span>Bytes</span><strong>{number(alert.get("src_bytes", 0))}</strong></div>
    <div class="evidence"><span>Score</span><strong>{safe(alert.get("anomaly_score", 0))}</strong></div>
    <div class="evidence"><span>OS Guess</span><strong>{safe(alert.get("os_guess"))}</strong></div>
    <div class="evidence"><span>Streak</span><strong>{number(alert.get("streak", 0))}</strong></div>
  </div>
</div>
""",
                unsafe_allow_html=True,
            )

    with b:
        st.markdown('<div class="section-title">Investigation Snapshot</div>', unsafe_allow_html=True)
        st.markdown(
            f"""
<div class="snapshot-card">
  <div class="snapshot-label">Most Active Source</div>
  <div class="snapshot-value">{safe(top_source)}</div>
  <div class="snapshot-detail">{number(top_source_events)} correlated events</div>
</div>
<div class="snapshot-card">
  <div class="snapshot-label">Dominant Vector</div>
  <div class="snapshot-value">{safe(top_attack)}</div>
  <div class="snapshot-detail">Most frequent attack classification</div>
</div>
<div class="snapshot-card">
  <div class="snapshot-label">Latest Source</div>
  <div class="snapshot-value">{safe(latest.get("ip", "N/A"))}</div>
  <div class="snapshot-detail">{safe(latest.get("attack_type", "N/A"))}</div>
</div>
<div class="note">
Latest event {safe(latest.get("event_id", "N/A"))} at {safe(latest.get("timestamp"))}.
Action state: {safe(action_for(latest))}.
</div>
""",
            unsafe_allow_html=True,
        )

    with c:
        st.markdown('<div class="section-title">Attack Mix</div>', unsafe_allow_html=True)
        attack_counts = df["attack_type"].value_counts()
        fig_mix = go.Figure(
            data=[
                go.Pie(
                    labels=attack_counts.index,
                    values=attack_counts.values,
                    hole=0.64,
                    marker=dict(
                        colors=["#20C20E", "#43e6ff", "#ffb84a", "#ff4d5e", "#20C20E", "#a57bff"],
                        line=dict(color="#050806", width=2),
                    ),
                    textinfo="none",
                    hovertemplate="<b>%{label}</b><br>Events: %{value}<br>%{percent}<extra></extra>",
                )
            ]
        )
        fig_mix.update_layout(
            height=254,
            margin=dict(l=4, r=4, t=4, b=4),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e8ffe0", family="JetBrains Mono"),
            showlegend=True,
            legend=dict(font=dict(size=10, color="#88a486"), orientation="v"),
            annotations=[
                dict(
                    text="VECTOR",
                    x=0.5,
                    y=0.5,
                    showarrow=False,
                    font=dict(color="#20C20E", size=12, family="JetBrains Mono"),
                )
            ],
        )
        st.plotly_chart(fig_mix, width="stretch")

    st.divider()

    t1, t2 = st.columns([1.25, 1])
    with t1:
        st.markdown('<div class="section-title">Anomaly Timeline</div>', unsafe_allow_html=True)
        timeline = df.reset_index().rename(columns={"index": "sequence"})
        color_map = {"CRITICAL": "#ff4d5e", "HIGH": "#ffb84a"}
        fig_time = go.Figure()
        for level in ["CRITICAL", "HIGH"]:
            subset = timeline[timeline["threat_level"] == level]
            if subset.empty:
                continue
            fig_time.add_trace(
                go.Scatter(
                    x=subset["sequence"] + 1,
                    y=subset["anomaly_score"],
                    mode="lines+markers",
                    name=level,
                    line=dict(color=color_map[level], width=2),
                    marker=dict(size=9, color=color_map[level], line=dict(color="#050806", width=1)),
                    customdata=subset[["event_id", "ip", "attack_type", "timestamp", "ports_hit"]],
                    hovertemplate=(
                        "<b>%{customdata[0]}</b><br>"
                        "Source: %{customdata[1]}<br>"
                        "Vector: %{customdata[2]}<br>"
                        "Time: %{customdata[3]}<br>"
                        "Ports: %{customdata[4]}<br>"
                        "Score: %{y}<extra></extra>"
                    ),
                )
            )
        fig_time.update_layout(
            height=318,
            margin=dict(l=44, r=16, t=12, b=42),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#09110c",
            font=dict(color="#88a486", family="JetBrains Mono"),
            xaxis=dict(title="Event Sequence", gridcolor="rgba(32,194,14,0.08)", linecolor="#213020"),
            yaxis=dict(title="Anomaly Score", gridcolor="rgba(32,194,14,0.08)", linecolor="#213020"),
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#e8ffe0")),
        )
        st.plotly_chart(fig_time, width="stretch")

    with t2:
        st.markdown('<div class="section-title">Source Pressure</div>', unsafe_allow_html=True)
        source_profile = (
            df.groupby("ip", as_index=False)
            .agg(
                events=("ip", "size"),
                critical=("threat_level", lambda x: int((x == "CRITICAL").sum())),
                blocked=("blocked", "max"),
                packets=("packets", "sum"),
                ports=("ports_hit", "max"),
                score=("anomaly_score", "max"),
                os=("os_guess", lambda x: x.mode().iloc[0] if not x.mode().empty else "Unknown"),
            )
            .sort_values(["critical", "events", "ports"], ascending=False)
            .head(8)
        )
        fig_sources = go.Figure(
            go.Bar(
                x=source_profile["events"],
                y=source_profile["ip"],
                orientation="h",
                marker=dict(
                    color=source_profile["ports"],
                    colorscale=[[0, "#1c321f"], [0.55, "#20C20E"], [1, "#ff4d5e"]],
                    line=dict(color="#050806", width=1),
                ),
                text=source_profile["events"],
                customdata=source_profile[["critical", "ports", "packets", "score", "os"]],
                hovertemplate=(
                    "Source: %{y}<br>"
                    "Events: %{x}<br>"
                    "Critical: %{customdata[0]}<br>"
                    "Max Ports: %{customdata[1]}<br>"
                    "Packets: %{customdata[2]}<br>"
                    "Max Score: %{customdata[3]}<br>"
                    "OS: %{customdata[4]}<extra></extra>"
                ),
            )
        )
        fig_sources.update_layout(
            height=318,
            margin=dict(l=88, r=16, t=12, b=42),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#09110c",
            font=dict(color="#88a486", family="JetBrains Mono"),
            xaxis=dict(title="Events", gridcolor="rgba(32,194,14,0.08)", linecolor="#213020"),
            yaxis=dict(autorange="reversed", gridcolor="rgba(32,194,14,0.06)", linecolor="#213020"),
        )
        st.plotly_chart(fig_sources, width="stretch")

    st.divider()

    tab_summary, tab_evidence, tab_registry = st.tabs(
        ["Source Profiles", "Port And Payload Evidence", "Raw Event Registry"]
    )

    with tab_summary:
        st.markdown('<div class="section-title">Per-Source Investigation Profile</div>', unsafe_allow_html=True)
        profile_view = source_profile.rename(
            columns={
                "ip": "Source IP",
                "events": "Events",
                "critical": "Critical",
                "blocked": "Blocked",
                "packets": "Packets",
                "ports": "Max Ports",
                "score": "Max Score",
                "os": "OS Guess",
            }
        )
        st.dataframe(profile_view, width="stretch", hide_index=True)

    with tab_evidence:
        st.markdown('<div class="section-title">Evidence Ranking</div>', unsafe_allow_html=True)
        e1, e2 = st.columns(2)
        with e1:
            ports_rank = df.sort_values(["ports_hit", "packets"], ascending=False).head(12)
            fig_ports = go.Figure(
                go.Bar(
                    x=ports_rank["ports_hit"],
                    y=ports_rank["event_id"],
                    orientation="h",
                    marker=dict(color="#20C20E", line=dict(color="#050806", width=1)),
                    customdata=ports_rank[["ip", "attack_type", "timestamp"]],
                    hovertemplate="Event: %{y}<br>Ports: %{x}<br>IP: %{customdata[0]}<br>%{customdata[1]}<br>%{customdata[2]}<extra></extra>",
                )
            )
            fig_ports.update_layout(
                height=330,
                margin=dict(l=82, r=12, t=8, b=38),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#09110c",
                font=dict(color="#88a486", family="JetBrains Mono"),
                xaxis=dict(title="Unique Ports", gridcolor="rgba(32,194,14,0.08)"),
                yaxis=dict(autorange="reversed"),
            )
            st.plotly_chart(fig_ports, width="stretch")
        with e2:
            payload_rank = df.sort_values(["src_bytes", "packets"], ascending=False).head(12)
            fig_payload = go.Figure(
                go.Bar(
                    x=payload_rank["src_bytes"],
                    y=payload_rank["event_id"],
                    orientation="h",
                    marker=dict(color="#43e6ff", line=dict(color="#050806", width=1)),
                    customdata=payload_rank[["ip", "attack_type", "packets"]],
                    hovertemplate="Event: %{y}<br>Bytes: %{x}<br>IP: %{customdata[0]}<br>%{customdata[1]}<br>Packets: %{customdata[2]}<extra></extra>",
                )
            )
            fig_payload.update_layout(
                height=330,
                margin=dict(l=82, r=12, t=8, b=38),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#09110c",
                font=dict(color="#88a486", family="JetBrains Mono"),
                xaxis=dict(title="Bytes", gridcolor="rgba(67,230,255,0.10)"),
                yaxis=dict(autorange="reversed"),
            )
            st.plotly_chart(fig_payload, width="stretch")

    with tab_registry:
        st.markdown('<div class="section-title">Full Alert Ledger</div>', unsafe_allow_html=True)
        display_cols = [
            "event_id",
            "timestamp",
            "ip",
            "attack_type",
            "threat_level",
            "blocked",
            "packets",
            "ports_hit",
            "src_bytes",
            "anomaly_score",
            "os_guess",
            "streak",
        ]
        available = [col for col in display_cols if col in df.columns]
        registry = df[available].sort_index(ascending=False).rename(
            columns={
                "event_id": "Event ID",
                "timestamp": "Time",
                "ip": "Source IP",
                "attack_type": "Vector",
                "threat_level": "Threat",
                "blocked": "Blocked",
                "packets": "Packets",
                "ports_hit": "Ports",
                "src_bytes": "Bytes",
                "anomaly_score": "Score",
                "os_guess": "OS Guess",
                "streak": "Streak",
            }
        )
        st.dataframe(registry, width="stretch", hide_index=True)

st.divider()
st.markdown(
    f"""
<div class="note">
ARGUS investigation console // alerts source: {safe(LOG_FILE)} // rendered {safe(latest_sync)}
</div>
""",
    unsafe_allow_html=True,
)

import time as _time
_time.sleep(2)
st.rerun()
