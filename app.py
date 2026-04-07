"""
app.py  —  NetGuard IDS Dashboard  (Multi-User Edition)
Run:  streamlit run app.py

Login system:
  • admin  / admin123  →  Admin panel + full dashboard
  • Any registered user → Personal dashboard (own alerts only)
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

# ── Local modules ──────────────────────────────────────────────────────────
import packet_sniffer as ps
from detector     import analyze_packet
from domain_lookup import resolve_ip
from email_alert  import send_alert
from user_logger  import log_user_attack, log_user_traffic, get_user_attacks, get_user_stats
import simulator
from login_page   import render_login_page
from admin_panel  import render_admin_panel

# ══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="NetGuard IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════
# CSS
# ══════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
:root {
  --bg-base:#050a0f; --bg-card:#0b1320; --bg-panel:#0f1c2d;
  --accent:#00e5ff; --accent2:#00ff99; --danger:#ff3860;
  --warn:#ffdd57; --text:#cdd9e5; --muted:#506070; --border:#1e3048;
}
html,body,[data-testid="stAppViewContainer"]{background:var(--bg-base)!important;color:var(--text)!important;font-family:'Rajdhani',sans-serif!important;}
[data-testid="stSidebar"]{background:#0f1c2d!important;border-right:1px solid var(--border);}
[data-testid="stHeader"]{background:transparent!important;}
[data-testid="metric-container"]{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:18px 20px!important;box-shadow:0 0 18px rgba(0,229,255,.05);}
[data-testid="metric-container"] label{color:var(--muted)!important;font-size:.8rem!important;letter-spacing:.1em!important;text-transform:uppercase;}
[data-testid="metric-container"] [data-testid="stMetricValue"]{font-family:'Share Tech Mono',monospace!important;font-size:2.2rem!important;color:var(--accent)!important;}
.stDataFrame{border:1px solid var(--border)!important;border-radius:8px;}
thead tr th{background:#091525!important;color:var(--accent)!important;font-size:.75rem!important;letter-spacing:.12em;}
.stButton>button{background:transparent!important;border:1px solid var(--accent)!important;color:var(--accent)!important;border-radius:6px;font-family:'Rajdhani',sans-serif;font-weight:600;letter-spacing:.08em;transition:all .2s;}
.stButton>button:hover{background:var(--accent)!important;color:#000!important;}
.sec-header{font-family:'Share Tech Mono',monospace;font-size:.7rem;letter-spacing:.2em;color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--border);padding-bottom:6px;margin-bottom:14px;}
.dot-live{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent2);box-shadow:0 0 8px var(--accent2);animation:pulse 1.4s infinite;}
.dot-off{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted);}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.role-admin{background:rgba(255,56,96,.15);color:#ff8fa3;border:1px solid rgba(255,56,96,.3);border-radius:4px;padding:2px 8px;font-size:.7rem;letter-spacing:.1em;font-family:'Share Tech Mono',monospace;}
.role-user{background:rgba(0,229,255,.1);color:#00e5ff;border:1px solid rgba(0,229,255,.2);border-radius:4px;padding:2px 8px;font-size:.7rem;letter-spacing:.1em;font-family:'Share Tech Mono',monospace;}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════
# AUTH GATE — show login page if not logged in
# ══════════════════════════════════════════════════════════════════════════
if not st.session_state.get("logged_in"):
    render_login_page()
    st.stop()

# ── Shortcuts ──────────────────────────────────────────────────────────────
CURRENT_USER = st.session_state.get("username", "unknown")
CURRENT_ROLE = st.session_state.get("role", "user")
IS_ADMIN     = CURRENT_ROLE == "admin"

# ══════════════════════════════════════════════════════════════════════════
# Per-user session state initialisation
# ══════════════════════════════════════════════════════════════════════════
def _init_state():
    defaults = {
        "running":         False,
        "use_simulator":   True,
        "alerts":          deque(maxlen=200),
        "attack_counts":   defaultdict(int),
        "top_attackers":   defaultdict(int),
        "total_packets":   0,
        "last_processed":  0,
        "pkt_timeline":    deque(maxlen=120),
        "_last_tick_ts":   time.time(),
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ══════════════════════════════════════════════════════════════════════════
# Process new packets  (attributed to current user)
# ══════════════════════════════════════════════════════════════════════════
def _process_new_packets():
    packets   = ps.get_packets()
    new_start = st.session_state["last_processed"]
    new_pkts  = packets[new_start:]
    if not new_pkts:
        return

    for pkt in new_pkts:
        st.session_state["total_packets"] += 1
        alert = analyze_packet(pkt)
        if alert:
            src  = alert["src_ip"]
            dom  = resolve_ip(src)
            alert["domain"] = dom
            st.session_state["alerts"].appendleft(alert)
            st.session_state["attack_counts"][alert["attack_type"]] += 1
            st.session_state["top_attackers"][src] += 1
            # ← store with username attribution
            log_user_attack(CURRENT_USER, alert, domain=dom)
            send_alert(alert["attack_type"], src, dom, alert.get("dst_port", 0))
        else:
            log_user_traffic(CURRENT_USER, pkt)

    st.session_state["last_processed"] = len(packets)

    now = time.time()
    if now - st.session_state["_last_tick_ts"] >= 2.0:
        st.session_state["pkt_timeline"].append(
            (datetime.now().strftime("%H:%M:%S"), len(new_pkts))
        )
        st.session_state["_last_tick_ts"] = now

# ══════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    # Logo
    st.markdown("""
    <div style='text-align:center;padding:12px 0 6px'>
      <span style='font-size:2rem'>🛡️</span><br>
      <span style='font-family:"Share Tech Mono",monospace;font-size:1rem;color:#00e5ff;letter-spacing:.18em'>NETGUARD</span><br>
      <span style='font-size:.6rem;color:#506070;letter-spacing:.15em'>INTRUSION DETECTION</span>
    </div>
    """, unsafe_allow_html=True)

    # User info
    role_badge = f"<span class='role-{'admin' if IS_ADMIN else 'user'}'>{'⚡ ADMIN' if IS_ADMIN else '👤 USER'}</span>"
    st.markdown(f"""
    <div style='background:#0b1320;border:1px solid #1e3048;border-radius:8px;
                padding:10px 14px;margin:8px 0 14px;'>
      <div style='font-family:"Share Tech Mono",monospace;font-size:.8rem;color:#00e5ff;margin-bottom:4px'>
        {CURRENT_USER.upper()}
      </div>
      <div>{role_badge}</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    # Status
    dot = '<span class="dot-live"></span>' if st.session_state["running"] else '<span class="dot-off"></span>'
    label = "MONITORING ACTIVE" if st.session_state["running"] else "MONITOR OFFLINE"
    st.markdown(f"<div style='font-size:.72rem;letter-spacing:.12em;color:#506070'>{dot}&nbsp; {label}</div>", unsafe_allow_html=True)
    st.write("")

    use_sim = st.toggle("Use Traffic Simulator", value=st.session_state["use_simulator"])
    st.session_state["use_simulator"] = use_sim

    c1, c2 = st.columns(2)
    with c1:
        if st.button("▶  START", use_container_width=True):
            if not st.session_state["running"]:
                if use_sim:
                    simulator.start()
                else:
                    ps.start_sniffing()
                st.session_state["running"] = True
                st.rerun()
    with c2:
        if st.button("■  STOP", use_container_width=True):
            if st.session_state["running"]:
                if use_sim:
                    simulator.stop()
                else:
                    ps.stop_sniffing()
                st.session_state["running"] = False
                st.rerun()

    if st.button("🗑  Clear Session Data", use_container_width=True):
        for k in ["alerts","attack_counts","top_attackers","total_packets","last_processed","pkt_timeline"]:
            if k in st.session_state:
                del st.session_state[k]
        ps.packet_store.clear()
        _init_state()
        st.rerun()

    st.divider()

    # Detection rules
    st.markdown("<div class='sec-header'>Detection Rules</div>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-size:.72rem;color:#506070;line-height:1.9'>
      🔴 SYN Flood — 100 SYN/10s<br>
      🟠 Port Scan — 15 ports/10s<br>
      🟡 Brute Force — 20 hits/10s<br>
      🔵 DDoS — 300 pkt/10s<br>
      🟣 DNS Tunnel — 40 DNS/10s
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    # Logout
    if st.button("🚪  Logout", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# ══════════════════════════════════════════════════════════════════════════
# Process packets
# ══════════════════════════════════════════════════════════════════════════
if st.session_state["running"]:
    _process_new_packets()

# ══════════════════════════════════════════════════════════════════════════
# PAGE HEADER
# ══════════════════════════════════════════════════════════════════════════
role_label = "ADMIN CONSOLE" if IS_ADMIN else "USER DASHBOARD"
st.markdown(f"""
<div style='padding:8px 0 4px'>
  <span style='font-family:"Share Tech Mono",monospace;font-size:1.5rem;color:#00e5ff;letter-spacing:.12em'>
    NETGUARD IDS
  </span>
  <span style='font-size:.75rem;color:#506070;letter-spacing:.12em;margin-left:14px'>{role_label}</span>
</div>
<div style='font-size:.7rem;color:#2a4060;margin-bottom:16px'>
  Logged in as <b style='color:#00e5ff'>{CURRENT_USER}</b> &nbsp;·&nbsp; Last refresh: {datetime.now().strftime('%H:%M:%S')}
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════
# ADMIN PANEL (full tab if admin)
# ══════════════════════════════════════════════════════════════════════════
if IS_ADMIN:
    main_tab, admin_tab = st.tabs(["📊  My Dashboard", "🔐  Admin Panel"])
    with admin_tab:
        render_admin_panel()
else:
    main_tab = st.container()

# ══════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD (same for all users — shows their own data)
# ══════════════════════════════════════════════════════════════════════════
with main_tab:
    # ── KPI row ─────────────────────────────────────────────────────────
    k1, k2, k3, k4, k5 = st.columns(5)
    total_attacks    = sum(st.session_state["attack_counts"].values())
    unique_attackers = len(st.session_state["top_attackers"])
    most_common      = max(st.session_state["attack_counts"], key=st.session_state["attack_counts"].get) \
                       if st.session_state["attack_counts"] else "—"
    top_ip           = max(st.session_state["top_attackers"],  key=st.session_state["top_attackers"].get) \
                       if st.session_state["top_attackers"] else "—"

    k1.metric("📦 Total Packets",    f"{st.session_state['total_packets']:,}")
    k2.metric("🚨 Attacks Detected", f"{total_attacks:,}")
    k3.metric("👥 Unique Attackers", f"{unique_attackers:,}")
    k4.metric("⚔️  Top Attack Type",  most_common)
    k5.metric("🎯 Top Attacker IP",   top_ip)
    st.write("")

    # ── Live Traffic + Attack Distribution ──────────────────────────────
    left, right = st.columns([3, 2], gap="medium")

    with left:
        st.markdown("<div class='sec-header'>▌ Live Traffic Feed</div>", unsafe_allow_html=True)
        packets = ps.get_packets()
        if packets:
            df = pd.DataFrame(packets[-60:])
            def _row_style(row):
                if row.get("attack_type"):
                    return ["background-color:rgba(255,56,96,.18)"] * len(row)
                return [""] * len(row)
            show_cols = ["timestamp","src_ip","dst_ip","protocol","dst_port","tcp_flags","attack_type"]
            available = [c for c in show_cols if c in df.columns]
            df_show = df[available].tail(30).copy()
            if "timestamp" in df_show.columns:
                df_show["timestamp"] = df_show["timestamp"].str[11:19]
            df_show = df_show.rename(columns={
                "timestamp":"Time","src_ip":"Source IP","dst_ip":"Dest IP",
                "protocol":"Proto","dst_port":"Port","tcp_flags":"Flags","attack_type":"Attack"
            })
            st.dataframe(df_show.style.apply(_row_style, axis=1),
                         use_container_width=True, height=320, hide_index=True)
        else:
            st.info("No packets captured yet. Start the monitor to begin.")

    with right:
        st.markdown("<div class='sec-header'>▌ Attack Distribution</div>", unsafe_allow_html=True)
        ac = st.session_state["attack_counts"]
        if ac:
            colors = ["#ff3860","#ff7f50","#ffdd57","#00e5ff","#a855f7","#00ff99"]
            fig = go.Figure(go.Pie(
                labels=list(ac.keys()), values=list(ac.values()), hole=.55,
                marker=dict(colors=colors[:len(ac)], line=dict(color="#050a0f", width=2)),
                textinfo="label+percent", textfont=dict(family="Rajdhani", size=12, color="#cdd9e5"),
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False, margin=dict(t=10,b=10,l=10,r=10), height=300,
                annotations=[dict(text=f"<b>{total_attacks}</b><br>attacks",
                                  x=0.5, y=0.5,
                                  font=dict(size=14,color="#00e5ff",family="Share Tech Mono"),
                                  showarrow=False)],
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown("""<div style='height:280px;display:flex;align-items:center;justify-content:center;
                color:#2a4060;font-family:"Share Tech Mono",monospace;font-size:.8rem'>
                NO ATTACKS DETECTED</div>""", unsafe_allow_html=True)

    # ── Timeline + Top Attackers ─────────────────────────────────────────
    t_col, a_col = st.columns([3, 2], gap="medium")

    with t_col:
        st.markdown("<div class='sec-header'>▌ Real-time Packet Activity</div>", unsafe_allow_html=True)
        timeline = list(st.session_state["pkt_timeline"])
        if len(timeline) >= 2:
            fig2 = go.Figure()
            fig2.add_trace(go.Scatter(
                x=[t[0] for t in timeline], y=[t[1] for t in timeline],
                mode="lines", line=dict(color="#00e5ff", width=2),
                fill="tozeroy", fillcolor="rgba(0,229,255,0.07)",
            ))
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(showgrid=False, color="#2a4060", tickfont=dict(size=9)),
                yaxis=dict(showgrid=True, gridcolor="#0f1c2d", color="#2a4060", tickfont=dict(size=9)),
                margin=dict(t=10,b=30,l=40,r=10), height=260, showlegend=False,
            )
            st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown("""<div style='height:240px;display:flex;align-items:center;justify-content:center;
                color:#2a4060;font-family:"Share Tech Mono",monospace;font-size:.8rem'>
                WAITING FOR DATA…</div>""", unsafe_allow_html=True)

    with a_col:
        st.markdown("<div class='sec-header'>▌ Top Attacker IPs (This Session)</div>", unsafe_allow_html=True)
        ta = st.session_state["top_attackers"]
        if ta:
            sorted_atk = sorted(ta.items(), key=lambda x: -x[1])[:8]
            fig3 = go.Figure(go.Bar(
                x=[x[1] for x in sorted_atk], y=[x[0] for x in sorted_atk],
                orientation="h",
                marker=dict(color=[x[1] for x in sorted_atk],
                            colorscale=[[0,"#1e3048"],[0.5,"#ff7f50"],[1,"#ff3860"]],
                            showscale=False),
                text=[x[1] for x in sorted_atk], textposition="outside",
                textfont=dict(color="#cdd9e5", size=10),
            ))
            fig3.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(showgrid=False, color="#2a4060", tickfont=dict(size=9)),
                yaxis=dict(showgrid=False, color="#cdd9e5", tickfont=dict(size=9), autorange="reversed"),
                margin=dict(t=10,b=20,l=10,r=40), height=260,
            )
            st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown("""<div style='height:240px;display:flex;align-items:center;justify-content:center;
                color:#2a4060;font-family:"Share Tech Mono",monospace;font-size:.8rem'>
                NO ATTACKER DATA</div>""", unsafe_allow_html=True)

    # ── Recent Alerts ─────────────────────────────────────────────────────
    st.write("")
    st.markdown("<div class='sec-header'>▌ Recent Attack Alerts (This Session)</div>", unsafe_allow_html=True)
    alerts = list(st.session_state["alerts"])
    if alerts:
        df_a = pd.DataFrame(alerts[:50])
        if "timestamp" in df_a.columns:
            df_a["timestamp"] = df_a["timestamp"].str[11:19]
        df_a = df_a.rename(columns={
            "timestamp":"Time","src_ip":"Attacker IP","domain":"Domain",
            "protocol":"Proto","dst_port":"Port","attack_type":"Attack Type"
        })
        show_a = [c for c in ["Time","Attacker IP","Domain","Proto","Port","Attack Type"] if c in df_a.columns]
        def _a_style(row):
            return ["background-color:rgba(255,56,96,.15);color:#ffb3c6"] * len(row)
        st.dataframe(df_a[show_a].style.apply(_a_style, axis=1),
                     use_container_width=True, height=240, hide_index=True)
    else:
        st.markdown("""<div style='padding:20px;text-align:center;color:#2a4060;
            font-family:"Share Tech Mono",monospace;font-size:.8rem;
            border:1px solid #1e3048;border-radius:8px'>
            ✅ &nbsp; NO ALERTS — NETWORK APPEARS CLEAN</div>""", unsafe_allow_html=True)

    # ── Historical Alerts from disk ──────────────────────────────────────
    st.write("")
    with st.expander("📂  View My Historical Alerts (from disk)"):
        hist = get_user_attacks(CURRENT_USER, limit=100)
        if hist:
            df_h = pd.DataFrame(hist)
            if "timestamp" in df_h.columns:
                df_h["timestamp"] = df_h["timestamp"].str[:19].str.replace("T"," ")
            show_h = [c for c in ["timestamp","src_ip","domain","protocol","dst_port","attack_type"] if c in df_h.columns]
            st.dataframe(df_h[show_h], use_container_width=True, hide_index=True, height=300)
            st.caption(f"Showing last {len(hist)} alerts logged to disk for your account.")
        else:
            st.info("No historical alerts for your account yet.")

    # ── Attack bar chart ─────────────────────────────────────────────────
    if ac:
        st.write("")
        st.markdown("<div class='sec-header'>▌ Attack Count by Type</div>", unsafe_allow_html=True)
        fig4 = go.Figure(go.Bar(
            x=list(ac.keys()), y=list(ac.values()),
            marker=dict(color=list(ac.values()),
                        colorscale=[[0,"#1e3048"],[0.4,"#00e5ff"],[0.8,"#ff7f50"],[1,"#ff3860"]],
                        showscale=False),
            text=list(ac.values()), textposition="outside",
            textfont=dict(color="#cdd9e5"),
        ))
        fig4.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(color="#cdd9e5", tickfont=dict(size=11, family="Rajdhani")),
            yaxis=dict(showgrid=True, gridcolor="#0f1c2d", color="#2a4060"),
            margin=dict(t=10,b=20,l=40,r=10), height=220,
        )
        st.plotly_chart(fig4, use_container_width=True, config={"displayModeBar": False})

# ══════════════════════════════════════════════════════════════════════════
# Footer + auto-refresh
# ══════════════════════════════════════════════════════════════════════════
st.divider()
st.markdown("""
<div style='text-align:center;font-size:.65rem;color:#2a4060;
            font-family:"Share Tech Mono",monospace;letter-spacing:.12em'>
  NETGUARD IDS · MULTI-USER EDITION · BUILT WITH SCAPY · STREAMLIT · PLOTLY
</div>""", unsafe_allow_html=True)

if st.session_state["running"]:
    time.sleep(2)
    st.rerun()
