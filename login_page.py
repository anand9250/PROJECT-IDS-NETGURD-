"""
login_page.py  —  Streamlit login & registration UI
Call render_login_page() from app.py when no user is logged in.
Returns nothing — writes to st.session_state on success.
"""

import streamlit as st
from auth import login_user, register_user


# Custom CSS injected once
_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

/* ── auth card ─────────────────────────────────────────────────────── */
.auth-wrap {
  display:flex; flex-direction:column; align-items:center;
  justify-content:center; min-height:80vh; padding:20px;
}
.auth-card {
  background:#0b1320; border:1px solid #1e3048; border-radius:14px;
  padding:40px 36px; width:100%; max-width:420px;
  box-shadow:0 8px 40px rgba(0,229,255,0.07);
}
.auth-logo {
  font-family:'Share Tech Mono',monospace; font-size:1.5rem;
  color:#00e5ff; letter-spacing:.18em; text-align:center; margin-bottom:4px;
}
.auth-sub {
  font-size:.7rem; color:#506070; letter-spacing:.14em;
  text-align:center; margin-bottom:28px;
  font-family:'Share Tech Mono',monospace;
}
.auth-tab-active {
  color:#00e5ff !important; border-bottom:2px solid #00e5ff !important;
  font-weight:700 !important;
}

/* ── override streamlit input ─────────────────────────────────────── */
input[type="text"], input[type="password"] {
  background:#050a0f !important; border:1px solid #1e3048 !important;
  color:#cdd9e5 !important; border-radius:7px !important;
  font-family:'Rajdhani',sans-serif !important;
}
input[type="text"]:focus, input[type="password"]:focus {
  border-color:#00e5ff !important; box-shadow:0 0 0 2px rgba(0,229,255,.1) !important;
}
.stButton > button {
  background: linear-gradient(135deg,#00a3cc,#0070aa) !important;
  color:#fff !important; border:none !important; border-radius:8px !important;
  font-family:'Rajdhani',sans-serif !important; font-weight:700 !important;
  letter-spacing:.1em !important; width:100%; padding:10px !important;
  margin-top:8px; font-size:1rem !important;
  transition:opacity .2s !important;
}
.stButton > button:hover { opacity:.88 !important; }
</style>
"""


def render_login_page():
    st.markdown(_CSS, unsafe_allow_html=True)

    st.markdown("""
    <div style='text-align:center;padding:40px 0 10px'>
      <div class='auth-logo'>🛡️ NETGUARD IDS</div>
      <div class='auth-sub'>NETWORK INTRUSION DETECTION SYSTEM</div>
    </div>
    """, unsafe_allow_html=True)

    # Tabs: Login | Register
    tab_login, tab_reg = st.tabs(["🔐  Login", "📝  Register"])

    # ── LOGIN ──────────────────────────────────────────────────────────
    with tab_login:
        st.write("")
        username = st.text_input("Username", key="li_user", placeholder="Enter your username")
        password = st.text_input("Password", type="password", key="li_pass", placeholder="Enter your password")
        st.write("")

        if st.button("Sign In", key="btn_login", use_container_width=True):
            if not username or not password:
                st.error("Please enter both username and password.")
            else:
                ok, result = login_user(username.strip(), password)
                if ok:
                    st.session_state["logged_in"]  = True
                    st.session_state["user"]        = result
                    st.session_state["username"]    = result["username"]
                    st.session_state["role"]        = result["role"]
                    st.success(f"Welcome back, {result['username']}!")
                    st.rerun()
                else:
                    st.error(result)

        st.markdown("""
        <div style='text-align:center;margin-top:16px;font-size:.75rem;color:#506070;
                    font-family:"Share Tech Mono",monospace'>
        </div>
        """, unsafe_allow_html=True)

    # ── REGISTER ───────────────────────────────────────────────────────
    with tab_reg:
        st.write("")
        new_user = st.text_input("Choose Username", key="reg_user", placeholder="Letters and numbers only")
        new_pass = st.text_input("Choose Password", type="password", key="reg_pass", placeholder="Min. 6 characters")
        conf_pass= st.text_input("Confirm Password",type="password", key="reg_conf", placeholder="Repeat your password")
        st.write("")

        if st.button("Create Account", key="btn_reg", use_container_width=True):
            if not new_user or not new_pass or not conf_pass:
                st.error("All fields are required.")
            elif new_pass != conf_pass:
                st.error("Passwords do not match.")
            else:
                ok, msg = register_user(new_user.strip(), new_pass, role="user")
                if ok:
                    st.success(msg + " Please log in.")
                else:
                    st.error(msg)
