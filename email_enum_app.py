"""
email_enum_app.py - Streamlit dashboard for passive email enumeration.

A web UI front-end for the acorns_email_enum.py OSINT workflow.
Run:
    python -m streamlit run email_enum_app.py

Passive only: reads public data / Hunter.io domain search. Never sends email,
never logs in. For AUTHORIZED assessments only.
"""

from __future__ import annotations

import io
import json

import pandas as pd
import streamlit as st

import acorns_email_enum as aee   # reuse the real logic (constants + functions)

# --------------------------------------------------------------------------- #
# Page config + styling
# --------------------------------------------------------------------------- #

st.set_page_config(page_title="MailRecon - Email OSINT", page_icon="📧",
                   layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
  .kpi-card { background: rgba(128,128,128,0.08); border:1px solid rgba(128,128,128,0.20);
    border-radius:14px; padding:16px 18px; text-align:center; }
  .kpi-value { font-size:2.0rem; font-weight:700; line-height:1.1; }
  .kpi-label { font-size:0.76rem; opacity:0.70; text-transform:uppercase;
    letter-spacing:0.06em; margin-top:4px; }
  .pill { display:inline-block; padding:3px 12px; margin:2px; border-radius:999px;
    font-size:0.8rem; font-weight:600; }
  .pill-high { background:rgba(46,160,67,0.18); border:1px solid rgba(46,160,67,0.5); color:#2ea043;}
  .pill-med  { background:rgba(210,153,34,0.18); border:1px solid rgba(210,153,34,0.5); color:#d29922;}
  .pill-low  { background:rgba(150,150,160,0.15); border:1px solid rgba(150,150,160,0.4); color:#9aa;}
  .code-dork { background:rgba(128,128,128,0.10); border-radius:8px; padding:8px 12px;
    font-family:Consolas,monospace; margin:4px 0; }
</style>
""", unsafe_allow_html=True)

for k, v in {"rows": [], "pattern": None, "tools": [], "ran": False, "target": "acorns.com"}.items():
    st.session_state.setdefault(k, v)


# --------------------------------------------------------------------------- #
# App-local Hunter.io lookup (takes the key from the UI, not an env var)
# --------------------------------------------------------------------------- #

def hunter_lookup(domain: str, api_key: str):
    """Call Hunter.io domain-search and return (results, confirmed_pattern)."""
    import requests
    r = requests.get("https://api.hunter.io/v2/domain-search",
                     params={"domain": domain, "api_key": api_key}, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", {}) or {}
    pattern = data.get("pattern")
    out = []
    for e in data.get("emails", []) or []:
        val = (e.get("value") or "").strip().lower()
        if not val:
            continue
        name = ((e.get("first_name") or "") + " " + (e.get("last_name") or "")).strip() or "(no name)"
        out.append({
            "name": name, "title": e.get("position") or "", "email": val,
            "source": "Hunter.io", "format": pattern or "{f}{last}",
            "confidence": aee.hunter_confidence_label(e.get("confidence")),
        })
    return out, pattern


def kpi(col, value, label):
    col.markdown(f'<div class="kpi-card"><div class="kpi-value">{value}</div>'
                 f'<div class="kpi-label">{label}</div></div>', unsafe_allow_html=True)


def conf_pill(c):
    cls = {"High": "pill-high", "Medium": "pill-med", "Low": "pill-low"}.get(c, "pill-low")
    return f'<span class="pill {cls}">{c}</span>'


# --------------------------------------------------------------------------- #
# Sidebar - controls
# --------------------------------------------------------------------------- #

with st.sidebar:
    st.title("📧 MailRecon")
    st.caption("Passive email enumeration & OSINT")

    target = st.text_input("Target domain", value=st.session_state["target"]).strip().lower()

    st.subheader("Data sources")
    use_hunter = st.toggle("Hunter.io (API)", value=True)
    api_key = st.text_input("Hunter.io API key", type="password",
                            help="Your key is used only for this lookup and is not stored.")
    use_pattern = st.toggle("Pattern derivation (named execs)", value=True)

    run = st.button("🚀 Run enumeration", type="primary", use_container_width=True)
    st.caption("Passive only - no email sent, no login. Authorized use only.")


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #

if run:
    if not target:
        st.sidebar.error("Enter a target domain.")
    else:
        st.session_state["target"] = target
        tools, pattern, hunter_rows = [], None, []
        with st.status("Running passive enumeration…", expanded=True) as status:
            if use_hunter:
                if not api_key:
                    status.write("⚠️ Hunter.io skipped - no API key entered.")
                else:
                    status.write("🔎 Querying Hunter.io domain search…")
                    try:
                        hunter_rows, pattern = hunter_lookup(target, api_key)
                        tools.append("Hunter.io")
                        status.write(f"✅ Hunter.io: {len(hunter_rows)} emails, confirmed pattern {pattern!r}")
                    except Exception as exc:
                        status.write(f"❌ Hunter.io failed: {type(exc).__name__}")

            pattern_rows = []
            if use_pattern:
                status.write("🧩 Deriving emails for named executives…")
                # Temporarily point the module's target at the chosen domain.
                aee.TARGET = target
                pattern_rows = aee.derive_from_pattern(pattern)
                status.write(f"✅ Derived {len(pattern_rows)} candidate emails "
                             f"(pattern: {pattern or '{first}.{last}'})")

            rows = aee.merge_results(hunter_rows, pattern_rows)
            st.session_state.update(rows=rows, pattern=pattern, tools=tools, ran=True)
            status.update(label=f"Done - {target}", state="complete", expanded=False)


# --------------------------------------------------------------------------- #
# Main view
# --------------------------------------------------------------------------- #

st.title("Email Enumeration — Passive OSINT")

if not st.session_state["ran"]:
    st.info("Enter a target domain (and your Hunter.io key for live results) in the "
            "sidebar, then click **Run enumeration**.")
    st.stop()

rows = st.session_state["rows"]
df = pd.DataFrame(rows)[["name", "title", "email", "source", "format", "confidence"]] if rows else pd.DataFrame()
df.columns = ["Name", "Title", "Email", "Source", "Format", "Confidence"] if not df.empty else df.columns

# KPI cards
total = len(rows)
high = sum(1 for r in rows if r["confidence"] == "High")
med = sum(1 for r in rows if r["confidence"] == "Medium")
low = sum(1 for r in rows if r["confidence"] == "Low")
fmt = st.session_state["pattern"] or "{first}.{last} (assumed)"

c1, c2, c3, c4, c5 = st.columns(5)
kpi(c1, total, "Total Emails")
kpi(c2, high, "High")
kpi(c3, med, "Medium")
kpi(c4, low, "Low")
kpi(c5, fmt, "Confirmed Format")

st.caption("Tools used: " + (", ".join(st.session_state["tools"]) or "pattern derivation only"))
st.divider()

tab1, tab2, tab3 = st.tabs(["📋 Results", "🔎 Google Dorks", "ℹ️ Methodology"])

with tab1:
    if df.empty:
        st.warning("No results.")
    else:
        q = st.text_input("Search", placeholder="name, email, title…")
        conf_pick = st.multiselect("Confidence", ["High", "Medium", "Low"])
        view = df.copy()
        if q:
            view = view[view.apply(lambda r: q.lower() in " ".join(map(str, r.values)).lower(), axis=1)]
        if conf_pick:
            view = view[view["Confidence"].isin(conf_pick)]
        st.caption(f"Showing {len(view)} of {len(df)} emails")
        st.dataframe(view, use_container_width=True, hide_index=True)

        d1, d2 = st.columns(2)
        d1.download_button("⬇️ Download CSV", view.to_csv(index=False).encode("utf-8"),
                           file_name=f"{st.session_state['target']}_email_enumeration.csv",
                           mime="text/csv", use_container_width=True)
        d2.download_button("⬇️ Download JSON",
                           json.dumps(view.to_dict(orient="records"), indent=2).encode("utf-8"),
                           file_name=f"{st.session_state['target']}_email_enumeration.json",
                           mime="application/json", use_container_width=True)

with tab2:
    st.write("Run these manually in a browser (Google dorking cannot be automated):")
    for dork in (f'site:{st.session_state["target"]} "@{st.session_state["target"]}"',
                 f'"@{st.session_state["target"]}" -site:{st.session_state["target"]}',
                 'site:linkedin.com/in "Acorns"'):
        st.markdown(f'<div class="code-dork">{dork}</div>', unsafe_allow_html=True)

with tab3:
    st.markdown("""
**Sources & trust**

- **Hunter.io** — live domain search. Confidence from Hunter's own score
  (≥80 = High, 50–79 = Medium, else Low). These are real, tool-confirmed emails.
- **Pattern (derived)** — public executive names mapped to the organization's
  confirmed email pattern. High for clean official names, Medium for likely
  nicknames (Pete→Peter, Liz→Elizabeth…), Low for third-party-sourced names.

**Confidence legend**
""", unsafe_allow_html=True)
    st.markdown(conf_pill("High") + " verified / high tool score &nbsp; "
                + conf_pill("Medium") + " corroborated / nickname &nbsp; "
                + conf_pill("Low") + " third-party / unverified", unsafe_allow_html=True)
    st.caption("Passive OSINT only. No emails were sent and no accounts were accessed.")
