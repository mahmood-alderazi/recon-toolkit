"""
app.py — Enterprise Asset Discovery & Technology Profiling dashboard (Streamlit).

Run:
    python -m streamlit run app.py

First-time Playwright setup (only needed for the optional screenshot module):
    python -m playwright install chromium
"""

from __future__ import annotations

import json
import os
from collections import Counter

import pandas as pd
import streamlit as st

import recon

# --------------------------------------------------------------------------- #
# Page config & styling
# --------------------------------------------------------------------------- #

st.set_page_config(
    page_title="SubRecon — Asset Discovery & Tech Profiling",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .kpi-card { background: rgba(128,128,128,0.08);
        border: 1px solid rgba(128,128,128,0.20); border-radius: 14px;
        padding: 16px 18px; text-align: center; }
      .kpi-value { font-size: 2.0rem; font-weight: 700; line-height: 1.1; }
      .kpi-label { font-size: 0.78rem; opacity: 0.70; text-transform: uppercase;
                   letter-spacing: 0.06em; margin-top: 4px; }
      .tech-card { border: 1px solid rgba(128,128,128,0.20); border-radius: 12px;
        padding: 14px 16px; margin-bottom: 12px; background: rgba(128,128,128,0.05); }
      .tech-card h4 { margin: 0 0 8px 0; font-size: 0.95rem; }
      .pill { display:inline-block; padding: 2px 10px; margin: 3px 4px 0 0;
        border-radius: 999px; font-size: 0.78rem;
        background: rgba(80,160,255,0.15); border: 1px solid rgba(80,160,255,0.35); }
      .gallery-card { border: 1px solid rgba(128,128,128,0.20); border-radius: 12px;
        padding: 10px; margin-bottom: 12px; background: rgba(128,128,128,0.05); }
    </style>
    """,
    unsafe_allow_html=True,
)

# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #

for key, default in {
    "subdomains": {}, "endpoints": [], "screenshots": {},
    "wildcards": [], "services": [], "target": "", "ran": False,
}.items():
    st.session_state.setdefault(key, default)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def full_dataframe(endpoints) -> pd.DataFrame:
    """One row per endpoint with every telemetry dimension (used for export)."""
    if not endpoints:
        return pd.DataFrame()
    df = pd.DataFrame([e.as_row() for e in endpoints])
    for col in ("sources", "cdn", "cms", "frontend", "cloud", "versions", "sec_missing"):
        if col in df.columns:
            df[col] = df[col].apply(lambda v: ", ".join(v) if isinstance(v, list) else v)
    return df


def kpi_card(col, value, label):
    col.markdown(
        f'<div class="kpi-card"><div class="kpi-value">{value}</div>'
        f'<div class="kpi-label">{label}</div></div>',
        unsafe_allow_html=True,
    )


def search_filter(df: pd.DataFrame, query: str) -> pd.DataFrame:
    if not query:
        return df
    q = query.lower()
    mask = df.apply(lambda r: q in " ".join(map(str, r.values)).lower(), axis=1)
    return df[mask]


def bool_icon(v) -> str:
    return "✅" if v else "❌"


# --------------------------------------------------------------------------- #
# Sidebar — controls
# --------------------------------------------------------------------------- #

with st.sidebar:
    st.title("🛰️ SubRecon")
    st.caption("Asset discovery & technology profiling")

    target = st.text_input("Target domain", value=st.session_state["target"],
                           placeholder="example.com").strip().lower()

    st.subheader("Discovery modules")
    st.caption("100% free · passive · no API key")
    use_crtsh = st.toggle("Certificate Transparency (crt.sh)", value=True)
    use_hackertarget = st.toggle("HackerTarget (passive DNS)", value=True)
    use_anubis = st.toggle("Anubis DB (passive DNS)", value=True)

    st.subheader("Inspection modules")
    do_probe = st.toggle("HTTP/HTTPS probing + fingerprint", value=True)
    do_ssl = st.toggle("SSL/TLS handshake inspection", value=True)
    do_asn = st.toggle("IP org / cloud lookup (RDAP)", value=True,
                       help="Passive ARIN RDAP lookup tagging each IP with its owner")
    do_wildcards = st.toggle("Wildcard & DNS catch-all analysis", value=True,
                             help="Passive: reads wildcards from CT logs, tests catch-all with a 2s DNS timeout")
    do_services = st.toggle("Passive ports & protocols (DNS)", value=True,
                            help="Maps MX/NS/SPF/web records to standard service ports — no port scanning")
    do_shots = st.toggle("Screenshots (Playwright)", value=False,
                         help="Requires: python -m playwright install chromium")

    with st.expander("Advanced"):
        timeout = st.slider("HTTP timeout (s)", 3, 30, recon.DEFAULT_TIMEOUT)
        workers = st.slider("Probe concurrency", 1, 60, recon.DEFAULT_PROBE_WORKERS)
        shot_limit = st.slider("Max screenshots", 1, 100, 25)

    run = st.button("🚀 Run reconnaissance", type="primary", use_container_width=True)
    st.caption("Use only against assets you are authorized to test.")


# --------------------------------------------------------------------------- #
# Run pipeline
# --------------------------------------------------------------------------- #

if run:
    if not target:
        st.sidebar.error("Enter a target domain first.")
    else:
        st.session_state["target"] = target
        st.session_state["screenshots"] = {}
        st.session_state["wildcards"] = []
        st.session_state["services"] = []
        status = st.status(f"Running reconnaissance on **{target}**", expanded=True)

        status.write("🔎 Collecting subdomains… (crt.sh can take 30–60s)")
        subs, messages, wildcards = recon.collect_subdomains(
            target, use_crtsh, use_hackertarget, use_anubis)
        st.session_state["subdomains"] = subs
        for m in messages:
            status.write(("⚠️ " if "FAILED" in m else "• ") + m)
        status.write(f"Found **{len(subs)}** unique hostnames.")

        # Wildcard architecture & DNS catch-all analysis
        if do_wildcards and wildcards:
            status.write(f"🌐 Analyzing {len(wildcards)} wildcard pattern(s)…")
            wbar = status.progress(0.0, text="Testing catch-all…")
            def _w(done, total):
                wbar.progress(done / total, text=f"Catch-all DNS test… {done}/{total}")
            wc_results = recon.analyze_wildcards(wildcards, progress=_w)
            st.session_state["wildcards"] = wc_results
            active = sum(1 for r in wc_results if r["resolves"])
            status.write(f"Wildcards: **{len(wc_results)}** found, **{active}** active catch-all.")

        if not subs:
            failed = [m for m in messages if "FAILED" in m]
            if failed:
                status.write("❌ All sources failed — likely a busy/blocked service. "
                             "Wait a moment and click **Run** again.")

        endpoints = []
        if do_probe and subs:
            pbar = status.progress(0.0, text="Probing hosts…")
            def _p(done, total):
                pbar.progress(done / total, text=f"Probing & fingerprinting… {done}/{total}")
            endpoints = recon.probe_hosts(subs, timeout=timeout, workers=workers,
                                          do_ssl=do_ssl, do_asn=do_asn, progress=_p)
            st.session_state["endpoints"] = endpoints
            live = sum(e.alive for e in endpoints)
            status.write(f"Probed {len(endpoints)} hosts — **{live}** live.")
        elif not do_probe:
            endpoints = [recon.Endpoint(host=h, sources=s) for h, s in subs.items()]
            st.session_state["endpoints"] = endpoints

        # Passive infrastructure & services (DNS record → port/protocol mapping)
        if do_services and target:
            status.write("🛰️ Mapping passive services (MX / NS / SPF / web)…")
            svc_rows, svc_msgs = recon.discover_services(
                target, st.session_state["endpoints"])
            st.session_state["services"] = svc_rows
            for m in svc_msgs:
                status.write("• " + m)

        if do_shots and st.session_state["endpoints"]:
            live_eps = [e for e in st.session_state["endpoints"] if e.alive][:shot_limit]
            if live_eps:
                sbar = status.progress(0.0, text="Capturing screenshots…")
                def _s(done, total):
                    sbar.progress(done / total, text=f"Screenshots… {done}/{total}")
                try:
                    shots = recon.capture_screenshots(live_eps, progress=_s)
                    for e in st.session_state["endpoints"]:
                        if e.host in shots:
                            e.screenshot = shots[e.host]
                    st.session_state["screenshots"] = shots
                    status.write(f"Captured **{len(shots)}** screenshots.")
                except Exception as exc:
                    status.write(f"⚠️ Screenshot module failed: {exc}. "
                                 "Run `python -m playwright install chromium`.")

        st.session_state["ran"] = True
        if not subs and any("FAILED" in m for m in messages):
            status.update(label=f"No results for {target} — source(s) failed, retry",
                          state="error", expanded=True)
        else:
            status.update(label=f"Done — {target}", state="complete", expanded=False)


# --------------------------------------------------------------------------- #
# Main view
# --------------------------------------------------------------------------- #

st.title("Asset Discovery & Technology Profiling")

if not st.session_state["ran"]:
    st.info("Enter a target domain in the sidebar and click **Run reconnaissance**.")
    st.stop()

endpoints = st.session_state["endpoints"]
subs = st.session_state["subdomains"]
shots = st.session_state["screenshots"]
df_all = full_dataframe(endpoints)

# --- KPI cards ---------------------------------------------------------------
total = len(subs)
live = sum(1 for e in endpoints if e.alive)
ok200 = sum(1 for e in endpoints if e.status_code == 200)
weak_ssl = sum(1 for e in endpoints if e.ssl_weak)
exposed = sum(1 for e in endpoints if e.alive and e.sec_score < 4)

c1, c2, c3, c4, c5 = st.columns(5)
kpi_card(c1, total, "Discovered")
kpi_card(c2, live, "Live Endpoints")
kpi_card(c3, ok200, "HTTP 200s")
kpi_card(c4, weak_ssl, "Weak TLS")
kpi_card(c5, exposed, "Missing Sec Headers")

# --- Unified export ----------------------------------------------------------
with st.container():
    e1, e2, _ = st.columns([1, 1, 4])
    if not df_all.empty:
        e1.download_button(
            "⬇️ Full telemetry CSV",
            data=df_all.to_csv(index=False).encode("utf-8"),
            file_name=f"{st.session_state['target']}_telemetry.csv",
            mime="text/csv", use_container_width=True,
        )
        e2.download_button(
            "⬇️ Full telemetry JSON",
            data=json.dumps([e.as_row() for e in endpoints], indent=2, default=str).encode("utf-8"),
            file_name=f"{st.session_state['target']}_telemetry.json",
            mime="application/json", use_container_width=True,
        )

st.divider()

tab1, tab2, tab3, tab4, tab6, tab7, tab5 = st.tabs([
    "📋 Asset Inventory", "🔐 SSL/TLS Telemetry",
    "🧩 Technology Matrix", "🛡️ Security Posture",
    "🌐 Wildcard Intelligence", "🛰️ Passive Ports & Protocols", "🖼️ Gallery",
])

# ============================ Tab 1: Asset Inventory ========================= #
with tab1:
    if df_all.empty:
        st.warning("No endpoints to display.")
    else:
        cols = ["host", "status_code", "url", "redirect_to", "server",
                "latency_ms", "ip", "net_org", "content_type", "alive", "sources"]
        inv = df_all[[c for c in cols if c in df_all.columns]].rename(columns={
            "host": "Hostname", "status_code": "HTTP", "url": "Final URL",
            "redirect_to": "Redirect", "server": "Server", "latency_ms": "Latency (ms)",
            "ip": "IP", "net_org": "Org / Cloud", "content_type": "Content-Type",
            "alive": "Live", "sources": "Sources",
        })
        q = st.text_input("Search inventory", placeholder="host, server, IP…", key="q_inv")
        view = search_filter(inv, q)
        st.caption(f"Showing {len(view)} of {len(inv)} assets")
        st.dataframe(view, use_container_width=True, hide_index=True)

# ============================ Tab 2: SSL/TLS Telemetry ======================= #
with tab2:
    ssl_rows = [e for e in endpoints if e.ssl_ok or e.ssl_error]
    if not ssl_rows:
        st.info("No SSL telemetry. Enable **SSL/TLS handshake inspection** and re-run.")
    else:
        sdf = pd.DataFrame([{
            "Hostname": e.host,
            "Protocol": e.ssl_protocol,
            "Cipher": e.ssl_cipher,
            "Issuer Org": e.ssl_issuer_org,
            "Issuer CN": e.ssl_issuer_cn,
            "Expiry": e.ssl_not_after,
            "Days Left": e.ssl_days_remaining,
            "SANs": e.ssl_san_count,
            "Validity": ("⚠️ " + e.ssl_weak_reason) if e.ssl_weak else ("✅ OK" if e.ssl_ok else "—"),
            "Error": e.ssl_error,
        } for e in ssl_rows])

        weak_only = st.checkbox("Show weak / expiring only", value=False)
        q = st.text_input("Search SSL", placeholder="issuer, protocol, host…", key="q_ssl")
        view = sdf[sdf["Validity"].str.startswith("⚠️")] if weak_only else sdf
        view = search_filter(view, q)
        st.caption(f"Showing {len(view)} of {len(sdf)} certificates")
        st.dataframe(view, use_container_width=True, hide_index=True)

# ============================ Tab 3: Technology Matrix ====================== #
with tab3:
    live_eps = [e for e in endpoints if e.alive]
    if not live_eps:
        st.info("No live endpoints fingerprinted.")
    else:
        def agg(attr):
            c = Counter()
            for e in live_eps:
                for item in getattr(e, attr):
                    c[item] += 1
            return c

        cats = [
            ("🖥️ CMS / Platform", agg("cms")),
            ("⚛️ Frontend Libraries", agg("frontend")),
            ("🌐 CDN / Edge", agg("cdn")),
            ("☁️ Cloud Storage", agg("cloud")),
            ("🏷️ Software Versions", agg("versions")),
        ]
        gcols = st.columns(2)
        for i, (title, counter) in enumerate(cats):
            with gcols[i % 2]:
                pills = "".join(
                    f'<span class="pill">{name} · {n}</span>'
                    for name, n in counter.most_common()
                ) or '<span style="opacity:0.6">none detected</span>'
                st.markdown(
                    f'<div class="tech-card"><h4>{title}</h4>{pills}</div>',
                    unsafe_allow_html=True,
                )

        st.markdown("##### Per-host technology breakdown")
        tdf = pd.DataFrame([{
            "Hostname": e.host,
            "CMS": ", ".join(e.cms),
            "Frontend": ", ".join(e.frontend),
            "CDN/Edge": ", ".join(e.cdn),
            "Cloud": ", ".join(e.cloud),
            "Versions": ", ".join(e.versions),
            "X-Powered-By": e.powered_by,
        } for e in live_eps])
        q = st.text_input("Search tech", placeholder="React, Cloudflare, WordPress…", key="q_tech")
        st.dataframe(search_filter(tdf, q), use_container_width=True, hide_index=True)

# ============================ Tab 4: Security Posture ======================= #
with tab4:
    live_eps = [e for e in endpoints if e.alive]
    if not live_eps:
        st.info("No live endpoints to assess.")
    else:
        secdf = pd.DataFrame([{
            "Hostname": e.host,
            "HSTS": bool_icon(e.sec_hsts),
            "CSP": bool_icon(e.sec_csp),
            "X-Frame-Options": bool_icon(e.sec_xfo),
            "X-Content-Type-Options": bool_icon(e.sec_xcto),
            "Score": f"{e.sec_score}/4",
            "Missing": ", ".join(e.sec_missing),
        } for e in live_eps])

        avg = sum(e.sec_score for e in live_eps) / len(live_eps)
        fully = sum(1 for e in live_eps if e.sec_score == 4)
        m1, m2, m3 = st.columns(3)
        m1.metric("Avg header score", f"{avg:.1f}/4")
        m2.metric("Fully hardened", f"{fully}/{len(live_eps)}")
        m3.metric("Missing ≥1 header", f"{len(live_eps) - fully}")

        only_gaps = st.checkbox("Show endpoints with gaps only", value=False)
        q = st.text_input("Search posture", placeholder="hostname…", key="q_sec")
        view = secdf[secdf["Score"] != "4/4"] if only_gaps else secdf
        st.dataframe(search_filter(view, q), use_container_width=True, hide_index=True)

# ====================== Tab: Wildcard Intelligence ========================= #
with tab6:
    wc = st.session_state["wildcards"]
    if not wc:
        st.info("No wildcard patterns found in Certificate Transparency logs, or the "
                "**Wildcard & DNS catch-all analysis** module was disabled.")
    else:
        total_wc = len(wc)
        active = sum(1 for r in wc if r["resolves"])
        max_depth = max((r["level"] for r in wc), default=0)

        k1, k2, k3 = st.columns(3)
        kpi_card(k1, total_wc, "Wildcards Identified")
        kpi_card(k2, active, "Active Catch-All Zones")
        kpi_card(k3, f"L{max_depth}", "Max Hierarchy Depth")
        st.write("")

        def badge(status: str) -> str:
            if status == "Active Catch-All":
                return "🔴 Active Catch-All"
            if status.startswith("NXDOMAIN"):
                return "🟢 NXDOMAIN (Protected)"
            return "🟠 Timeout / Unresolved"

        wdf = pd.DataFrame([{
            "Wildcard Domain": r["wildcard"],
            "Hierarchy Level": f"L{r['level']}",
            "Resolves?": "Yes" if r["resolves"] else "No",
            "Resolved IP / Status": r["ip"] if r["resolves"] else r["status"],
            "Security Implication": r["implication"],
            "_badge": badge(r["status"]),
        } for r in wc])

        show_active = st.checkbox("Show active catch-all only", value=False)
        q = st.text_input("Search wildcards", placeholder="*.app.target.com…", key="q_wc")
        view = wdf[wdf["_badge"].str.contains("Active")] if show_active else wdf
        if q:
            view = view[view.apply(lambda r: q.lower() in " ".join(map(str, r.values)).lower(), axis=1)]

        display = view.rename(columns={"_badge": "Status"})[
            ["Wildcard Domain", "Hierarchy Level", "Resolves?",
             "Resolved IP / Status", "Status", "Security Implication"]
        ]
        st.caption(f"Showing {len(display)} of {total_wc} wildcards")
        st.dataframe(display, use_container_width=True, hide_index=True)

        st.download_button(
            "⬇️ Download Wildcards CSV",
            data=display.to_csv(index=False).encode("utf-8"),
            file_name=f"{st.session_state['target']}_wildcards.csv",
            mime="text/csv",
        )

# ==================== Tab: Passive Ports & Protocols ======================= #
with tab7:
    svc = st.session_state["services"]
    if not svc:
        st.info("No passive services mapped. Enable **Passive ports & protocols (DNS)** "
                "and re-run. (Requires `dnspython`.)")
    else:
        st.caption("Passive service map — ports are **inferred from DNS records and edge "
                   "headers**, not from active port scanning. 'Live' = the DNS service or "
                   "web endpoint is publicly responding. Rows are consolidated per host.")

        agg = recon.aggregate_services(svc)   # one row per distinct hostname/category

        mail = sum(1 for r in agg if r["category"] == "mail")
        dns_n = sum(1 for r in agg if r["category"] == "dns")
        web = sum(1 for r in agg if r["category"] == "web")
        m1, m2, m3, m4 = st.columns(4)
        kpi_card(m1, len(agg), "Service Endpoints")
        kpi_card(m2, mail, "Mail Servers")
        kpi_card(m3, dns_n, "Name Servers")
        kpi_card(m4, web, "Web Hosts")
        st.write("")

        sdf = pd.DataFrame([{
            "Service Type": r["service"],
            "Associated Hostname": r["hostname"],
            "Standard Ports": r["ports"],
            "Protocols": r["protocols"],
            "Transport": r["transport"],
            "Provider/Role": r["provider"],
            "Live Verification Status": r["live"],
        } for r in agg])

        types = sorted(sdf["Service Type"].unique())
        fc1, fc2 = st.columns([1, 2])
        pick = fc1.multiselect("Service type", types)
        q = fc2.text_input("Search services", placeholder="hostname, provider, port…", key="q_svc")
        view = sdf[sdf["Service Type"].isin(pick)] if pick else sdf
        view = search_filter(view, q)
        st.caption(f"Showing {len(view)} of {len(sdf)} service endpoints")
        st.dataframe(view, use_container_width=True, hide_index=True)

        st.download_button(
            "⬇️ Download Passive Ports CSV",
            data=view.to_csv(index=False).encode("utf-8"),
            file_name=f"{st.session_state['target']}_passive_ports.csv",
            mime="text/csv",
        )

# ============================ Tab 5: Gallery ================================ #
with tab5:
    if not shots:
        st.info("No screenshots captured. Enable the **Screenshots** module and re-run "
                "(requires `python -m playwright install chromium`).")
    else:
        by_host = {e.host: e for e in endpoints}
        gcols = st.columns(3)
        for i, (host, path) in enumerate(sorted(shots.items())):
            with gcols[i % 3]:
                st.markdown('<div class="gallery-card">', unsafe_allow_html=True)
                if os.path.exists(path):
                    st.image(path, use_container_width=True)
                ep = by_host.get(host)
                meta = f"{ep.status_code or '—'} · {ep.title or ep.url}" if ep else ""
                st.markdown(f"**{host}**  \n<small style='opacity:.7'>{meta}</small>",
                            unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)
