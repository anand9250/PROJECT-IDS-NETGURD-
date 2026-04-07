"""
admin_panel.py  —  Admin-only dashboard panel
Shows: all users list, all attacks from all users, top IPs, user management
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime

from auth        import get_all_users, set_user_active, delete_user, register_user
from user_logger import get_all_attacks, get_admin_overview


def render_admin_panel():
    st.markdown("""
    <div style='background:rgba(255,56,96,.08);border:1px solid rgba(255,56,96,.3);
                border-radius:10px;padding:12px 20px;margin-bottom:20px;
                font-family:"Share Tech Mono",monospace;font-size:.75rem;color:#ff8fa3;
                letter-spacing:.12em'>
      🔴 &nbsp; ADMIN CONTROL PANEL &nbsp;—&nbsp; FULL SYSTEM VISIBILITY
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "👥  All Users",
        "🚨  All Attacks",
        "🎯  Top Attacker IPs",
        "⚙️  User Management",
    ])

    # ══════════════════════════════════════════════
    # TAB 1: ALL USERS
    # ══════════════════════════════════════════════
    with tab1:
        st.markdown("<div class='sec-header'>▌ Registered Users</div>", unsafe_allow_html=True)
        users = get_all_users()
        overview = get_admin_overview()

        if users:
            rows = []
            for u in users:
                uname   = u["username"]
                stats   = overview.get(uname, {})
                rows.append({
                    "Username":       uname,
                    "Role":           u["role"].upper(),
                    "Status":         "Active" if u.get("active", True) else "Disabled",
                    "Registered":     u.get("created_at", "")[:10],
                    "Last Login":     (u.get("last_login") or "Never")[:16].replace("T", " "),
                    "Total Attacks":  stats.get("total_attacks", 0),
                })
            df = pd.DataFrame(rows)

            def _user_style(row):
                if row["Role"] == "ADMIN":
                    return ["background-color:rgba(0,229,255,.08)"] * len(row)
                if row["Status"] == "Disabled":
                    return ["background-color:rgba(255,56,96,.08);color:#888"] * len(row)
                return [""] * len(row)

            st.dataframe(
                df.style.apply(_user_style, axis=1),
                use_container_width=True,
                hide_index=True,
                height=min(60 + len(rows) * 35, 400),
            )
            st.caption(f"Total registered users: {len(users)}")
        else:
            st.info("No users found.")

    # ══════════════════════════════════════════════
    # TAB 2: ALL ATTACKS FROM ALL USERS
    # ══════════════════════════════════════════════
    with tab2:
        st.markdown("<div class='sec-header'>▌ All Attacks — System-Wide</div>", unsafe_allow_html=True)

        all_attacks = get_all_attacks(limit=500)

        if all_attacks:
            col1, col2, col3 = st.columns(3)
            unique_ips    = len({a.get("src_ip") for a in all_attacks})
            unique_users  = len({a.get("username") for a in all_attacks})
            attack_types  = {}
            for a in all_attacks:
                t = a.get("attack_type", "Unknown")
                attack_types[t] = attack_types.get(t, 0) + 1
            top_type = max(attack_types, key=attack_types.get) if attack_types else "—"

            col1.metric("🚨 Total Attacks",     len(all_attacks))
            col2.metric("👥 Users Affected",     unique_users)
            col3.metric("🎯 Unique Attacker IPs",unique_ips)
            st.write("")

            df = pd.DataFrame(all_attacks)
            show_cols = ["timestamp","username","src_ip","domain","protocol","dst_port","attack_type"]
            available = [c for c in show_cols if c in df.columns]
            df_show = df[available].copy()
            if "timestamp" in df_show.columns:
                df_show["timestamp"] = df_show["timestamp"].str[:19].str.replace("T"," ")
            df_show = df_show.rename(columns={
                "timestamp":"Time","username":"User","src_ip":"Attacker IP",
                "domain":"Domain","protocol":"Proto","dst_port":"Port","attack_type":"Attack Type"
            })

            def _atk_style(row):
                colors = {
                    "SYN Flood":  "rgba(255,56,96,.18)",
                    "DDoS":       "rgba(0,122,255,.18)",
                    "Port Scan":  "rgba(255,160,50,.18)",
                    "DNS Tunneling":"rgba(168,85,247,.18)",
                }
                return [f"background-color:{colors.get(row.get('Attack Type',''), 'rgba(255,56,96,.1)')}"] * len(row)

            st.dataframe(
                df_show.style.apply(_atk_style, axis=1),
                use_container_width=True,
                hide_index=True,
                height=400,
            )
        else:
            st.markdown("""
            <div style='padding:30px;text-align:center;color:#2a4060;
                        font-family:"Share Tech Mono",monospace;font-size:.8rem;
                        border:1px solid #1e3048;border-radius:8px'>
              ✅ NO ATTACKS RECORDED YET ACROSS ANY USER SESSION
            </div>""", unsafe_allow_html=True)

    # ══════════════════════════════════════════════
    # TAB 3: TOP ATTACKER IPs (GLOBAL)
    # ══════════════════════════════════════════════
    with tab3:
        st.markdown("<div class='sec-header'>▌ Top Attacker IPs — All Users Combined</div>", unsafe_allow_html=True)

        all_attacks = get_all_attacks(limit=1000)
        if all_attacks:
            ip_counts    = {}
            ip_users     = {}
            ip_types     = {}
            ip_domains   = {}
            for a in all_attacks:
                ip  = a.get("src_ip", "Unknown")
                usr = a.get("username", "?")
                atype = a.get("attack_type", "?")
                dom   = a.get("domain", "Unknown")
                ip_counts[ip]  = ip_counts.get(ip, 0) + 1
                ip_users.setdefault(ip, set()).add(usr)
                ip_types.setdefault(ip, set()).add(atype)
                if dom != "Unknown":
                    ip_domains[ip] = dom

            # Table
            rows = []
            for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:30]:
                rows.append({
                    "Attacker IP":    ip,
                    "Domain":         ip_domains.get(ip, "Unknown"),
                    "Total Alerts":   cnt,
                    "Attack Types":   ", ".join(sorted(ip_types.get(ip, set()))),
                    "Users Targeted": len(ip_users.get(ip, set())),
                })
            df_ip = pd.DataFrame(rows)
            st.dataframe(df_ip, use_container_width=True, hide_index=True, height=min(400, 60+len(rows)*35))

            # Bar chart
            st.write("")
            top20 = sorted(ip_counts.items(), key=lambda x: -x[1])[:15]
            ips   = [x[0] for x in top20]
            cnts  = [x[1] for x in top20]
            fig = go.Figure(go.Bar(
                x=cnts, y=ips, orientation="h",
                marker=dict(color=cnts, colorscale=[[0,"#1e3048"],[0.5,"#ff7f50"],[1,"#ff3860"]], showscale=False),
                text=cnts, textposition="outside", textfont=dict(color="#cdd9e5", size=11),
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(showgrid=False, color="#2a4060", tickfont=dict(size=9)),
                yaxis=dict(showgrid=False, color="#cdd9e5", tickfont=dict(size=10), autorange="reversed"),
                margin=dict(t=10, b=20, l=10, r=60), height=max(260, len(top20)*22),
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No attack data available yet.")

    # ══════════════════════════════════════════════
    # TAB 4: USER MANAGEMENT
    # ══════════════════════════════════════════════
    with tab4:
        st.markdown("<div class='sec-header'>▌ User Management</div>", unsafe_allow_html=True)

        users = get_all_users()
        non_admin = [u for u in users if u["username"] != "admin"]

        # ── Enable / Disable user
        st.markdown("**Enable / Disable User Account**")
        user_names = [u["username"] for u in non_admin]
        if user_names:
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                sel_user = st.selectbox("Select User", user_names, key="mgmt_user")
            with col2:
                if st.button("✅ Enable",  use_container_width=True, key="btn_enable"):
                    set_user_active(sel_user, True)
                    st.success(f"{sel_user} enabled.")
                    st.rerun()
            with col3:
                if st.button("🚫 Disable", use_container_width=True, key="btn_disable"):
                    set_user_active(sel_user, False)
                    st.warning(f"{sel_user} disabled.")
                    st.rerun()
        else:
            st.info("No non-admin users found.")

        st.divider()

        # ── Delete user
        st.markdown("**Delete User Account**")
        if user_names:
            del_col1, del_col2 = st.columns([3, 1])
            with del_col1:
                del_user = st.selectbox("Select User to Delete", user_names, key="del_user")
            with del_col2:
                if st.button("🗑 Delete", use_container_width=True, key="btn_del"):
                    ok, msg = delete_user(del_user)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

        st.divider()

        # ── Create new user (admin creates accounts with any role)
        st.markdown("**Create New User Account**")
        c1, c2, c3, c4 = st.columns([2, 2, 1, 1])
        with c1:
            nu = st.text_input("Username", key="adm_nu", placeholder="username")
        with c2:
            np = st.text_input("Password", type="password", key="adm_np", placeholder="password")
        with c3:
            role = st.selectbox("Role", ["user", "admin"], key="adm_role")
        with c4:
            st.write("")
            st.write("")
            if st.button("Create", use_container_width=True, key="adm_create"):
                ok, msg = register_user(nu, np, role=role)
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
