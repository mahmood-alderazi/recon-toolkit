"""
recon.py — passive asset discovery + deep technology/SSL profiling helpers.

Pure logic module (no Streamlit imports) so functions stay testable and reusable:
  * Data collection   -> crt.sh Certificate Transparency + HackerTarget + Anubis DB
  * Web probing        -> concurrent HTTP/HTTPS metadata + latency
  * SSL/TLS telemetry  -> raw handshake inspection (protocol, cipher, issuer, expiry)
  * Tech fingerprinting-> headers + DOM signatures (CDN, CMS, frontend, cloud, sec headers)
  * Visual recon       -> Playwright screenshots

All network calls are read-only OSINT / active probing of the target's own hosts.
"""

from __future__ import annotations

import concurrent.futures as cf
import os
import re
import random
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Callable, Iterable

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

USER_AGENT = "subrecon/2.0 (+asset-discovery; https://github.com/)"
SCREENSHOT_DIR = "screenshots"
DEFAULT_TIMEOUT = 10          # seconds per HTTP request
DEFAULT_PROBE_WORKERS = 20    # concurrent probe threads
SSL_TIMEOUT = 4               # seconds max per TLS handshake
EXPIRY_WARN_DAYS = 30         # flag certs expiring within this many days
LEGACY_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Endpoint:
    """One probed hostname and every dimension of telemetry we collected."""
    host: str
    # --- HTTP layer ---
    url: str = ""
    scheme: str = ""
    alive: bool = False
    status_code: int | None = None
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: str = ""
    redirect_to: str = ""
    latency_ms: float | None = None
    ip: str = ""
    net_org: str = ""            # organization / cloud provider (RDAP)
    net_name: str = ""           # RDAP network handle/name
    error: str = ""
    sources: list[str] = field(default_factory=list)
    # --- SSL/TLS layer ---
    ssl_ok: bool = False
    ssl_protocol: str = ""
    ssl_cipher: str = ""
    ssl_issuer_org: str = ""
    ssl_issuer_cn: str = ""
    ssl_not_after: str = ""
    ssl_days_remaining: int | None = None
    ssl_san_count: int | None = None
    ssl_weak: bool = False
    ssl_weak_reason: str = ""
    ssl_error: str = ""
    # --- Technology fingerprint ---
    cdn: list[str] = field(default_factory=list)
    cms: list[str] = field(default_factory=list)
    frontend: list[str] = field(default_factory=list)
    cloud: list[str] = field(default_factory=list)
    powered_by: str = ""
    versions: list[str] = field(default_factory=list)   # passive software versions
    # --- Security posture ---
    sec_hsts: bool = False
    sec_csp: bool = False
    sec_xfo: bool = False
    sec_xcto: bool = False
    sec_missing: list[str] = field(default_factory=list)
    sec_score: int = 0            # 0-4 headers present
    # --- Visual ---
    screenshot: str = ""

    def as_row(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# 1. Data collection (passive OSINT)
# --------------------------------------------------------------------------- #

def _clean_host(name: str) -> str:
    if not name:
        return ""
    name = name.strip().lower().lstrip("*.").rstrip(".")
    name = name.split("\n")[0].strip()
    if not name or "@" in name or " " in name:
        return ""
    return name


def _valid_subdomain(host: str, target: str) -> bool:
    if not host or not _HOSTNAME_RE.match(host):
        return False
    return host == target or host.endswith("." + target)


def _get_with_retries(url: str, timeout: int, retries: int = 3,
                      backoff: float = 3.0) -> requests.Response:
    """
    GET with retries. crt.sh in particular is slow/flaky — it will 404, 502, or
    time out on one call and succeed on the next. Raises the last error if all
    attempts fail.
    """
    headers = {"User-Agent": "Mozilla/5.0 (compatible; subrecon/2.0)"}
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            # Retry transient/empty responses; accept a real 200 with a body.
            if resp.status_code == 200 and resp.text.strip():
                return resp
            last_exc = requests.HTTPError(f"HTTP {resp.status_code}")
        except Exception as exc:
            last_exc = exc
        if attempt < retries - 1:
            time.sleep(backoff * (attempt + 1))
    raise last_exc or RuntimeError("request failed")


def _valid_wildcard(wc: str, target: str) -> bool:
    """A '*.<something>.target' (or '*.target') entry scoped to the target."""
    if not wc.startswith("*."):
        return False
    base = wc[2:]
    return base == target or base.endswith("." + target)


def _parse_crtsh_rows(rows: list, target: str) -> tuple[set[str], set[str]]:
    """Extract (plain hostnames, wildcard patterns) from crt.sh certificate rows."""
    hosts: set[str] = set()
    wildcards: set[str] = set()
    for entry in rows:
        for field_name in ("name_value", "common_name"):
            raw = entry.get(field_name, "") or ""
            for candidate in raw.split("\n"):            # multiline SAN strings
                cand = candidate.strip().lower().rstrip(".")
                if cand.startswith("*.") and _valid_wildcard(cand, target):
                    wildcards.add(cand)
                host = _clean_host(cand)
                if _valid_subdomain(host, target):
                    hosts.add(host)
    return hosts, wildcards


def fetch_crtsh(target: str, timeout: int = 40) -> tuple[set[str], set[str], str]:
    """
    Query crt.sh CT logs and extract both subdomains and wildcard (*.) patterns
    from SAN / common-name entries. Returns (hosts, wildcards, status_message).
    """
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        resp = _get_with_retries(url, timeout=timeout)
        rows = resp.json()
        hosts, wildcards = _parse_crtsh_rows(rows, target)
        return (hosts, wildcards,
                f"crt.sh: {len(rows)} certs → {len(hosts)} subdomains, {len(wildcards)} wildcards")
    except Exception as exc:
        return set(), set(), f"crt.sh FAILED ({type(exc).__name__}) — service is often busy, try again"


def fetch_hackertarget(target: str, timeout: int = 20) -> tuple[set[str], str]:
    """
    Query the free, unauthenticated HackerTarget HostSearch API for passive DNS
    hostnames. Response is plain text, one 'hostname,ip' pair per line.
    Returns (hosts, status_message).
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={target}"
    found: set[str] = set()
    try:
        resp = _get_with_retries(url, timeout=timeout)
        text = resp.text.strip()
        # The API returns 200 with an error sentence when rate-limited / empty.
        low = text.lower()
        if ("api count exceeded" in low or "error" in low
                or "no records" in low or "," not in text):
            return found, f"hackertarget FAILED (rate-limited or no data)"
        for line in text.splitlines():
            host = _clean_host(line.split(",")[0])
            if _valid_subdomain(host, target):
                found.add(host)
        return found, f"hackertarget: {len(found)} subdomains"
    except Exception as exc:
        return found, f"hackertarget FAILED ({type(exc).__name__})"


def fetch_anubis(target: str, timeout: int = 20) -> tuple[set[str], str]:
    """
    Query the free Anubis DB (jldc.me) for passive DNS hostnames.
    Response is a JSON array of subdomains. Returns (hosts, status_message).
    """
    url = f"https://jldc.me/anubis/subdomains/{target}"
    found: set[str] = set()
    try:
        resp = _get_with_retries(url, timeout=timeout)
        for item in resp.json():
            host = _clean_host(item)
            if _valid_subdomain(host, target):
                found.add(host)
        return found, f"anubis: {len(found)} subdomains"
    except Exception as exc:
        return found, f"anubis FAILED ({type(exc).__name__})"


def collect_subdomains(target: str, use_crtsh: bool = True,
                       use_hackertarget: bool = True,
                       use_anubis: bool = True
                       ) -> tuple[dict[str, list[str]], list[str], set[str]]:
    """
    Run enabled free/passive collectors and merge + deduplicate across providers.
    Returns ({host: [sources]}, [status_messages], {wildcard_patterns}).
    """
    target = _clean_host(target)
    merged: dict[str, set[str]] = {}
    messages: list[str] = []
    wildcards: set[str] = set()

    if use_crtsh:
        hosts, wc, msg = fetch_crtsh(target)
        messages.append(msg)
        wildcards |= wc
        for host in hosts:
            merged.setdefault(host, set()).add("crt.sh")

    for enabled, label, fn in [(use_hackertarget, "hackertarget", fetch_hackertarget),
                               (use_anubis, "anubis", fetch_anubis)]:
        if not enabled:
            continue
        hosts, msg = fn(target)
        messages.append(msg)
        for host in hosts:
            merged.setdefault(host, set()).add(label)

    # Also scan the deduplicated passive hostnames for any wildcard references.
    for host in merged:
        if host.startswith("*.") and _valid_wildcard(host, target):
            wildcards.add(host)

    return {host: sorted(src) for host, src in sorted(merged.items())}, messages, wildcards


# --------------------------------------------------------------------------- #
# 1b. Wildcard architecture & DNS catch-all analysis (passive / non-intrusive)
# --------------------------------------------------------------------------- #

CATCHALL_DNS_TIMEOUT = 2   # seconds — strict per-lookup cap

_IMPLICATION = {
    "Active Catch-All": (
        "Wildcard DNS resolves any label — can mask subdomain takeovers and lets "
        "arbitrary hostnames (phishing, spoofed services) resolve under the zone."
    ),
    "NXDOMAIN (No Catch-All)": "Undefined labels are rejected — no catch-all exposure.",
    "Timeout / Unresolved": "Resolver did not answer in time — status undetermined.",
}


def wildcard_depth(wildcard: str) -> int:
    """
    Hierarchy depth of a wildcard pattern.
      *.target.com        -> 2   (target.com    = 2 labels)
      *.sub.target.com    -> 3   (sub.target.com= 3 labels)
      *.a.sub.target.com  -> 4+
    """
    base = wildcard[2:] if wildcard.startswith("*.") else wildcard
    base = base.strip(".")
    return base.count(".") + 1 if base else 0


def _catchall_probe(wildcard: str) -> dict:
    """
    Non-intrusive catch-all test: resolve a randomized synthetic label under the
    wildcard base with a strict 2s DNS timeout. No connection is opened.
    """
    base = wildcard[2:] if wildcard.startswith("*.") else wildcard
    label = f"probe-synthetic-check-{random.randint(10000, 99999)}"
    test_host = f"{label}.{base}"
    row = {
        "wildcard": wildcard, "base": base, "level": wildcard_depth(wildcard),
        "test_host": test_host, "resolves": False, "ip": "",
        "status": "Timeout / Unresolved", "implication": "",
    }
    try:
        socket.setdefaulttimeout(CATCHALL_DNS_TIMEOUT)
        ip = socket.gethostbyname(test_host)
        row.update(resolves=True, ip=ip, status="Active Catch-All")
    except socket.gaierror:
        row["status"] = "NXDOMAIN (No Catch-All)"
    except (socket.timeout, OSError):
        row["status"] = "Timeout / Unresolved"
    except Exception:
        row["status"] = "Timeout / Unresolved"
    row["implication"] = _IMPLICATION.get(row["status"], "")
    return row


def analyze_wildcards(wildcards: Iterable[str], workers: int = 20,
                      progress: Callable[[int, int], None] | None = None) -> list[dict]:
    """
    Concurrently run the passive catch-all test for every wildcard pattern.
    Uses a ThreadPoolExecutor; each DNS lookup is capped at 2 seconds.
    """
    wl = sorted(set(wildcards))
    total = len(wl)
    results: list[dict] = []
    if not wl:
        return results

    with cf.ThreadPoolExecutor(max_workers=max(1, min(workers, total))) as pool:
        futures = {pool.submit(_catchall_probe, w): w for w in wl}
        for i, fut in enumerate(cf.as_completed(futures), start=1):
            try:
                results.append(fut.result())
            except Exception:
                w = futures[fut]
                results.append({
                    "wildcard": w, "base": w[2:], "level": wildcard_depth(w),
                    "test_host": "", "resolves": False, "ip": "",
                    "status": "Timeout / Unresolved",
                    "implication": _IMPLICATION["Timeout / Unresolved"],
                })
            if progress:
                progress(i, total)

    results.sort(key=lambda r: (-r["level"], r["wildcard"]))
    return results


# --------------------------------------------------------------------------- #
# 1c. Passive infrastructure & services (DNS record → port/protocol mapping)
# --------------------------------------------------------------------------- #

# Provider inference tables: (substring, friendly label). First match wins.
_MX_PROVIDERS = [
    ("aspmx", "Google Workspace"), ("google", "Google Workspace"),
    ("googlemail", "Google Workspace"), ("protection.outlook", "Microsoft 365"),
    ("mail.protection", "Microsoft 365"), ("outlook", "Microsoft 365"),
    ("sendgrid", "SendGrid"), ("mailgun", "Mailgun"),
    ("amazonses", "Amazon SES"), ("amazonaws", "Amazon SES"),
    ("pphosted", "Proofpoint"), ("proofpoint", "Proofpoint"),
    ("mimecast", "Mimecast"), ("messagelabs", "Broadcom/Symantec"),
    ("barracuda", "Barracuda"), ("zoho", "Zoho Mail"),
]
_NS_PROVIDERS = [
    ("awsdns", "Amazon Route 53"), ("cloudflare", "Cloudflare"),
    ("googledomains", "Google Cloud DNS"), ("google", "Google Cloud DNS"),
    ("azure-dns", "Azure DNS"), ("nsone", "NS1"), ("ns1.", "NS1"),
    ("akam", "Akamai"), ("dnsmadeeasy", "DNS Made Easy"),
    ("dynect", "Oracle Dyn"), ("ultradns", "UltraDNS"),
    ("domaincontrol", "GoDaddy"), ("name-services", "Enom"),
]
_SPF_PROVIDERS = [
    ("_spf.google.com", "Google Workspace"), ("google.com", "Google Workspace"),
    ("sendgrid", "SendGrid"), ("zendesk", "Zendesk"), ("mailgun", "Mailgun"),
    ("amazonses", "Amazon SES"), ("spf.protection.outlook", "Microsoft 365"),
    ("outlook", "Microsoft 365"), ("mailchimp", "Mailchimp"),
    ("mandrill", "Mailchimp"), ("salesforce", "Salesforce"),
    ("pardot", "Salesforce Pardot"), ("hubspot", "HubSpot"),
    ("marketo", "Marketo"), ("mktomail", "Marketo"), ("zoho", "Zoho"),
    ("sparkpost", "SparkPost"), ("sendinblue", "Brevo"), ("brevo", "Brevo"),
]


def _match_provider(host: str, table: list[tuple[str, str]]) -> str:
    h = host.lower()
    for needle, label in table:
        if needle in h:
            return label
    return host


def _dns_query(name: str, rtype: str, timeout: int = 4) -> tuple[list[str], str]:
    """
    Resolve a DNS record type via dnspython. Returns (records, error_name).
    Never raises — NXDOMAIN, NoAnswer, timeouts and a missing dnspython all
    degrade to ([], reason).
    """
    try:
        import dns.resolver
    except ImportError:
        return [], "dnspython_missing"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(name, rtype)
        return [r.to_text() for r in answers], ""
    except Exception as exc:
        return [], type(exc).__name__


def discover_services(target: str, endpoints: list["Endpoint"] | None = None,
                      timeout: int = 4) -> tuple[list[dict], list[str]]:
    """
    Passive infrastructure map from public DNS records + already-probed web hosts.
    Returns (rows, status_messages). Each row is a service/port/protocol entry.
    """
    target = _clean_host(target)
    endpoints = endpoints or []
    rows: list[dict] = []
    messages: list[str] = []

    def add(service, host, port, proto, transport, provider, live):
        rows.append({
            "service": service, "hostname": host, "port": port, "protocol": proto,
            "transport": transport, "provider": provider, "live": live,
        })

    # --- MX → mail protocols (SMTP 25 / SMTPS 465 / Submission 587) ---
    mx, mx_err = _dns_query(target, "MX", timeout)
    for rec in mx:
        parts = rec.split()
        host = (parts[-1] if parts else rec).rstrip(".")
        provider = _match_provider(host, _MX_PROVIDERS)
        for port, proto in [(25, "SMTP"), (465, "SMTPS"), (587, "Submission/STARTTLS")]:
            add(f"Email / {proto}", host, port, proto, "TCP", provider, "Live (Active MX)")
    if mx_err and not mx:
        messages.append(f"MX: {mx_err}")

    # --- NS → DNS (port 53) ---
    ns, ns_err = _dns_query(target, "NS", timeout)
    for rec in ns:
        host = rec.rstrip(".")
        provider = _match_provider(host, _NS_PROVIDERS)
        add("DNS", host, 53, "DNS", "UDP/TCP", provider, "Live (Authoritative NS)")
    if ns_err and not ns:
        messages.append(f"NS: {ns_err}")

    # --- TXT / SPF include: → third-party email routing ---
    txt, txt_err = _dns_query(target, "TXT", timeout)
    includes: set[str] = set()
    for rec in txt:
        val = rec.strip().strip('"').replace('" "', "")
        if "v=spf1" in val.lower():
            for inc in re.findall(r'include:([^\s"]+)', val):
                includes.add(inc.lower().rstrip("."))
    for inc in sorted(includes):
        provider = _match_provider(inc, _SPF_PROVIDERS)
        add("Email Routing (SPF include)", inc, 25, "SMTP (authorized sender)",
            "TCP", provider, "Authorized Sender (SPF)")
    if txt_err and not txt:
        messages.append(f"TXT: {txt_err}")

    # --- Live web subdomains → HTTP/HTTPS (+ alt 8443 when proxied) ---
    for e in endpoints:
        if not getattr(e, "alive", False):
            continue
        provider = ", ".join(e.cdn) or e.net_org or "Direct origin"
        code = e.status_code
        live = f"Live (HTTP {code})" if code else "Live (HTTP responsive)"
        add("Web / Application", e.host, 80, "HTTP", "TCP", provider, live)
        add("Web / Application", e.host, 443, "HTTPS", "TCP", provider, live)
        if any("cloudflare" in c.lower() for c in e.cdn):
            add("Web / Application (alt)", e.host, 8443, "HTTPS-alt", "TCP",
                provider, live)

    messages.append(
        f"services: {len(mx)} MX, {len(ns)} NS, {len(includes)} SPF includes, "
        f"{sum(1 for e in endpoints if getattr(e,'alive',False))} live web → {len(rows)} rows"
    )
    return rows, messages


def _service_category(service: str) -> str:
    if service.startswith("Email Routing"):
        return "spf"
    if service.startswith("Email"):
        return "mail"
    if service.startswith("Web"):
        return "web"
    if service == "DNS":
        return "dns"
    return "other"


# Short protocol label per port for clean aggregated cells.
_PROTO_SHORT = {25: "SMTP", 465: "SMTPS", 587: "STARTTLS", 53: "DNS",
                80: "HTTP", 443: "HTTPS", 8443: "HTTPS-alt"}


def aggregate_services(rows: list[dict]) -> list[dict]:
    """
    Consolidate raw service rows into one row per (category, hostname), combining
    ports and protocols into single cells so each distinct host appears once.
    """
    groups: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []

    for r in rows:
        cat = _service_category(r["service"])
        key = (cat, r["hostname"])
        if key not in groups:
            groups[key] = {
                "category": cat, "hostname": r["hostname"],
                "ports": [], "protocols": [], "transports": [],
                "provider": r["provider"], "live": r["live"], "service": r["service"],
            }
            order.append(key)
        g = groups[key]
        if r["port"] not in g["ports"]:
            g["ports"].append(r["port"])
            g["protocols"].append(_PROTO_SHORT.get(r["port"], r["protocol"]))
        if r["transport"] not in g["transports"]:
            g["transports"].append(r["transport"])

    out: list[dict] = []
    for key in order:
        g = groups[key]
        cat = g["category"]
        if cat == "mail":
            service = f"Email ({g['provider']} MX)"
        elif cat == "web":
            service = "Web / Application"
        elif cat == "dns":
            service = "DNS"
        elif cat == "spf":
            service = "Email Routing (SPF include)"
        else:
            service = g["service"]
        out.append({
            "category": cat,
            "service": service,
            "hostname": g["hostname"],
            "ports": ", ".join(str(p) for p in g["ports"]),
            "protocols": ", ".join(g["protocols"]),
            "transport": ", ".join(g["transports"]),
            "provider": g["provider"],
            "live": g["live"],
        })
    return out


# --------------------------------------------------------------------------- #
# 2. SSL/TLS handshake inspection
# --------------------------------------------------------------------------- #

def _name_attr(x509_name, oid) -> str:
    try:
        attrs = x509_name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def inspect_ssl(host: str, port: int = 443, timeout: int = SSL_TIMEOUT) -> dict:
    """
    Establish a raw TLS connection and extract cryptographic telemetry.

    Uses an unverified context so expired / self-signed certs are still inspected
    (recon needs to *see* misconfiguration, not reject it). All socket / handshake
    errors are swallowed and reported via the 'error' field.
    """
    out = {
        "ssl_ok": False, "ssl_protocol": "", "ssl_cipher": "",
        "ssl_issuer_org": "", "ssl_issuer_cn": "", "ssl_not_after": "",
        "ssl_days_remaining": None, "ssl_san_count": None,
        "ssl_weak": False, "ssl_weak_reason": "", "ssl_error": "",
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                out["ssl_protocol"] = tls.version() or ""
                cipher = tls.cipher()
                out["ssl_cipher"] = cipher[0] if cipher else ""
                der = tls.getpeercert(binary_form=True)
    except (socket.timeout, ssl.SSLError, ConnectionResetError,
            ConnectionRefusedError, OSError) as exc:
        out["ssl_error"] = f"{type(exc).__name__}"
        return out
    except Exception as exc:  # last-resort guard, never break the run
        out["ssl_error"] = f"{type(exc).__name__}"
        return out

    # Parse the DER certificate. cryptography is optional; degrade gracefully.
    if der:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtensionOID

            cert = x509.load_der_x509_certificate(der)
            out["ssl_issuer_org"] = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
            out["ssl_issuer_cn"] = _name_attr(cert.issuer, NameOID.COMMON_NAME)

            try:
                not_after = cert.not_valid_after_utc          # cryptography >= 42
            except AttributeError:
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            out["ssl_not_after"] = not_after.strftime("%Y-%m-%d")
            days = (not_after - datetime.now(timezone.utc)).days
            out["ssl_days_remaining"] = days

            try:
                san = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value
                out["ssl_san_count"] = len(san.get_values_for_type(x509.DNSName))
            except Exception:
                out["ssl_san_count"] = 0
        except ImportError:
            out["ssl_error"] = "cryptography_not_installed"
        except Exception as exc:
            out["ssl_error"] = f"parse_{type(exc).__name__}"

    out["ssl_ok"] = True

    # --- weak-configuration flags ---
    reasons = []
    if out["ssl_protocol"] in LEGACY_PROTOCOLS:
        reasons.append(f"legacy protocol {out['ssl_protocol']}")
    d = out["ssl_days_remaining"]
    if d is not None:
        if d < 0:
            reasons.append("certificate expired")
        elif d <= EXPIRY_WARN_DAYS:
            reasons.append(f"expires in {d}d")
    if reasons:
        out["ssl_weak"] = True
        out["ssl_weak_reason"] = "; ".join(reasons)

    return out


# --------------------------------------------------------------------------- #
# 3. Technology & security fingerprinting
# --------------------------------------------------------------------------- #

# Header-based CDN / edge signatures: {label: (header, needle_or_None)}
_CDN_HEADER_SIGS = [
    ("Cloudflare", "server", "cloudflare"),
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "cf-cache-status", None),
    ("CloudFront", "x-amz-cf-id", None),
    ("CloudFront", "via", "cloudfront"),
    ("Akamai", "server", "akamai"),
    ("Akamai", "x-akamai-transformed", None),
    ("Fastly", "x-served-by", "cache"),
    ("Fastly", "via", "fastly"),
    ("AWS ALB", "server", "awselb"),
    ("Google Frontend", "server", "gse"),
    ("Vercel", "server", "vercel"),
    ("Vercel", "x-vercel-id", None),
    ("Netlify", "server", "netlify"),
]

_CLOUD_HEADER_SIGS = [
    ("AWS S3", "server", "amazons3"),
    ("AWS S3", "x-amz-request-id", None),
    ("Google Cloud Storage", "server", "uploadserver"),
    ("Google Cloud Storage", "x-goog-generation", None),
    ("Azure Blob", "server", "windows-azure-blob"),
    ("Azure Blob", "x-ms-request-id", None),
]

# DOM / script body signatures: {label: [needles]}
# Signatures are deliberately asset/path-specific (not bare brand names) to
# avoid false positives from customer logos, links, or marketing copy.
_CMS_BODY_SIGS = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json"],
    "Drupal": ["sites/all/", "sites/default/files", "drupal.settings"],
    "Joomla": ["/media/jui/", "com_content", "/media/system/js/"],
    "Zendesk": ["zdassets.com", "static.zdassets", ".zendesk.com/embeddable"],
    "Shopify": ["cdn.shopify.com", "x-shopify", "shopify.theme"],
}
_FRONTEND_BODY_SIGS = {
    "Next.js": ["/_next/static", "__next_data__", "__next"],
    "React": ["data-reactroot", "react-dom", "_reactlisten", "__reactcontainer"],
    "Vue.js": ["data-v-", "__vue__", "vue.runtime"],
    "Angular": ["ng-version", "ng-app", "angular"],
    "jQuery": ["jquery"],
    "Svelte": ["svelte-"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.bundle"],
}


def _detect(sigs: dict[str, list[str]], body: str) -> list[str]:
    hits = []
    for label, needles in sigs.items():
        if any(n in body for n in needles):
            hits.append(label)
    return hits


def _detect_headers(sigs, headers_lower: dict[str, str]) -> list[str]:
    hits = []
    for label, header, needle in sigs:
        if header in headers_lower:
            val = headers_lower[header]
            if needle is None or needle in val:
                if label not in hits:
                    hits.append(label)
    return hits


# Matches "product/version" tokens like nginx/1.25.3, awselb/2.0, Apache/2.4.52.
_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]*?)/(\d[\w.\-]*)")


def extract_versions(headers_ci: dict[str, str], generator: str) -> list[str]:
    """
    Passive software/version extraction from response headers + the HTML
    <meta name="generator"> tag. Never sends extra requests.
    """
    versions: list[str] = []

    def add(v: str):
        v = v.strip()
        if v and v not in versions:
            versions.append(v)

    # product/version pairs in banner-style headers
    for hk in ("server", "x-powered-by", "via", "x-generator"):
        raw = headers_ci.get(hk, "")
        for m in _VERSION_RE.finditer(raw):
            add(f"{m.group(1)} {m.group(2)}")

    # bare-version headers (value is just the version string)
    for hk, product in (("x-aspnet-version", "ASP.NET"),
                        ("x-aspnetmvc-version", "ASP.NET MVC")):
        if headers_ci.get(hk):
            add(f"{product} {headers_ci[hk].strip()}")

    # X-Powered-By values that carry no slash (e.g. "Next.js", "Express")
    xpb = headers_ci.get("x-powered-by", "").strip()
    if xpb and "/" not in xpb and not any(xpb.split()[0] in v for v in versions):
        add(xpb)

    # HTML generator tag, e.g. "WordPress 6.4.2", "Drupal 10 (https://…)"
    if generator:
        g = re.split(r"\s*\(", generator)[0].strip()
        if g:
            add(g)

    return versions


def fingerprint_tech(headers: dict, html: str) -> dict:
    """Detect CDN/edge, cloud storage, CMS, frontend frameworks, and versions."""
    headers_lower = {k.lower(): (v or "").lower() for k, v in headers.items()}
    headers_ci = {k.lower(): (v or "") for k, v in headers.items()}  # value case kept
    body = (html or "")[:250_000].lower()

    # meta generator gives an extra CMS hint + version string
    cms = _detect(_CMS_BODY_SIGS, body)
    generator = ""
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            generator = gen["content"]
            g = generator.lower()
            for name in ("wordpress", "drupal", "joomla", "wix", "ghost"):
                if name in g and name.capitalize() not in cms:
                    cms.append(name.capitalize())
    except Exception:
        pass

    powered = headers_ci.get("x-powered-by", "")

    return {
        "cdn": _detect_headers(_CDN_HEADER_SIGS, headers_lower),
        "cloud": _detect_headers(_CLOUD_HEADER_SIGS, headers_lower),
        "cms": sorted(set(cms)),
        "frontend": _detect(_FRONTEND_BODY_SIGS, body),
        "powered_by": powered,
        "versions": extract_versions(headers_ci, generator),
    }


def evaluate_security_headers(headers: dict) -> dict:
    """Check presence of the four core defensive response headers."""
    h = {k.lower(): v for k, v in headers.items()}
    checks = {
        "sec_hsts": "strict-transport-security",
        "sec_csp": "content-security-policy",
        "sec_xfo": "x-frame-options",
        "sec_xcto": "x-content-type-options",
    }
    labels = {
        "sec_hsts": "HSTS", "sec_csp": "CSP",
        "sec_xfo": "X-Frame-Options", "sec_xcto": "X-Content-Type-Options",
    }
    result, missing, score = {}, [], 0
    for key, header in checks.items():
        present = header in h
        result[key] = present
        if present:
            score += 1
        else:
            missing.append(labels[key])
    result["sec_missing"] = missing
    result["sec_score"] = score
    return result


# --------------------------------------------------------------------------- #
# 4. Web probing (orchestrates HTTP + SSL + fingerprint per host)
# --------------------------------------------------------------------------- #

def _extract_title(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip()[:200]
    except Exception:
        pass
    return ""


def _resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


# Cache RDAP results per IP — CDN farms share IPs across many subdomains, so this
# avoids hammering the registry with duplicate lookups.
_RDAP_CACHE: dict[str, tuple[str, str]] = {}
_RDAP_LOCK = threading.Lock()

# Friendly labels for common networks (RDAP org strings are noisy).
_ORG_ALIASES = [
    ("amazon", "Amazon.com / AWS"),
    ("aws", "Amazon.com / AWS"),
    ("cloudflare", "Cloudflare"),
    ("google", "Google Cloud / Google"),
    ("microsoft", "Microsoft / Azure"),
    ("azure", "Microsoft / Azure"),
    ("fastly", "Fastly"),
    ("akamai", "Akamai"),
    ("digitalocean", "DigitalOcean"),
    ("oracle", "Oracle Cloud"),
    ("linode", "Linode / Akamai"),
    ("hetzner", "Hetzner"),
    ("ovh", "OVH"),
    ("github", "GitHub"),
    ("shopify", "Shopify"),
    ("vercel", "Vercel"),
    ("squarespace", "Squarespace"),
]


def _friendly_org(raw: str) -> str:
    low = raw.lower()
    for needle, label in _ORG_ALIASES:
        if needle and needle in low:
            return label
    return raw


def _rdap_extract_org(data: dict) -> tuple[str, str]:
    """Pull (org, network_name) from an RDAP IP-network object."""
    net_name = data.get("name", "") or ""
    org = ""
    # Prefer a registrant/organization entity's vCard 'fn' (full name).
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        vcard = entity.get("vcardArray", [])
        fn = ""
        if isinstance(vcard, list) and len(vcard) == 2:
            for item in vcard[1]:
                if isinstance(item, list) and item and item[0] == "fn":
                    fn = item[3] if len(item) > 3 else ""
        if fn and ("registrant" in roles or "administrative" in roles or not org):
            org = fn
            if "registrant" in roles:
                break
    return org or net_name, net_name


def lookup_rdap(ip: str, timeout: int = 5) -> tuple[str, str]:
    """
    Passive IP -> org/cloud-provider lookup via ARIN RDAP. ARIN redirects to the
    authoritative RIR for non-ARIN space (requests follows it); rdap.org is used
    as a fallback. Returns (friendly_org, network_name); ("","") on failure.
    """
    if not ip:
        return "", ""
    with _RDAP_LOCK:
        if ip in _RDAP_CACHE:
            return _RDAP_CACHE[ip]

    result = ("", "")
    headers = {"User-Agent": "subrecon/2.0", "Accept": "application/rdap+json"}
    for url in (f"https://rdap.arin.net/registry/ip/{ip}",
                f"https://rdap.org/ip/{ip}"):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200 and resp.text.strip():
                org, net_name = _rdap_extract_org(resp.json())
                result = (_friendly_org(org), net_name)
                break
        except Exception:
            continue

    with _RDAP_LOCK:
        _RDAP_CACHE[ip] = result
    return result


def probe_host(host: str, timeout: int = DEFAULT_TIMEOUT,
               sources: list[str] | None = None, do_ssl: bool = True,
               do_asn: bool = True) -> Endpoint:
    """Probe one host over HTTPS then HTTP, then enrich with SSL + tech + RDAP telemetry."""
    ep = Endpoint(host=host, sources=sources or [])
    ep.ip = _resolve_ip(host)
    if do_asn and ep.ip:
        ep.net_org, ep.net_name = lookup_rdap(ep.ip)

    resp = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(
                url, headers={"User-Agent": USER_AGENT}, timeout=timeout,
                allow_redirects=True, verify=False,
            )
        except Exception as exc:
            ep.error = f"{scheme}: {type(exc).__name__}"
            resp = None
            continue

        ep.alive = True
        ep.scheme = scheme
        ep.url = url
        ep.status_code = resp.status_code
        ep.latency_ms = round(resp.elapsed.total_seconds() * 1000, 1)
        ep.server = resp.headers.get("Server", "")
        ep.content_type = resp.headers.get("Content-Type", "").split(";")[0]
        ep.content_length = resp.headers.get("Content-Length", "")
        ep.title = _extract_title(resp.text)
        ep.error = ""
        if resp.history:
            ep.redirect_to = resp.url
        break  # first successful scheme wins

    # Enrich alive hosts with fingerprint + security posture
    if resp is not None and ep.alive:
        tech = fingerprint_tech(dict(resp.headers), resp.text)
        ep.cdn, ep.cloud = tech["cdn"], tech["cloud"]
        ep.cms, ep.frontend = tech["cms"], tech["frontend"]
        ep.powered_by = tech["powered_by"]
        ep.versions = tech["versions"]

        sec = evaluate_security_headers(dict(resp.headers))
        ep.sec_hsts, ep.sec_csp = sec["sec_hsts"], sec["sec_csp"]
        ep.sec_xfo, ep.sec_xcto = sec["sec_xfo"], sec["sec_xcto"]
        ep.sec_missing, ep.sec_score = sec["sec_missing"], sec["sec_score"]

    # SSL handshake for responsive hosts (independent of HTTP scheme used)
    if do_ssl and ep.alive:
        for k, v in inspect_ssl(host).items():
            setattr(ep, k, v)

    return ep


def probe_hosts(host_sources: dict[str, list[str]], timeout: int = DEFAULT_TIMEOUT,
                workers: int = DEFAULT_PROBE_WORKERS, do_ssl: bool = True,
                do_asn: bool = True,
                progress: Callable[[int, int], None] | None = None) -> list[Endpoint]:
    """Concurrently probe every host. `progress(done, total)` fires as work completes."""
    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    except Exception:
        pass

    hosts = list(host_sources.items())
    total = len(hosts)
    results: list[Endpoint] = []

    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(probe_host, host, timeout, src, do_ssl, do_asn): host
            for host, src in hosts
        }
        for i, fut in enumerate(cf.as_completed(futures), start=1):
            try:
                results.append(fut.result())
            except Exception:
                results.append(Endpoint(host=futures[fut], error="probe_failed"))
            if progress:
                progress(i, total)

    results.sort(key=lambda e: (not e.alive, e.host))
    return results


# --------------------------------------------------------------------------- #
# 5. Visual reconnaissance (Playwright)
# --------------------------------------------------------------------------- #

def sanitize_filename(host: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host).strip("_") or "host"


def _capture_batch_sync(targets, out_dir, timeout_ms, progress) -> dict[str, str]:
    """Runs in a worker thread with no asyncio loop -> Playwright sync API is safe."""
    from playwright.sync_api import sync_playwright

    os.makedirs(out_dir, exist_ok=True)
    captured: dict[str, str] = {}
    total = len(targets)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True, user_agent=USER_AGENT,
            viewport={"width": 1280, "height": 800},
        )
        for i, (host, url) in enumerate(targets, start=1):
            path = os.path.join(out_dir, f"{sanitize_filename(host)}.png")
            try:
                page = context.new_page()
                page.goto(url, timeout=timeout_ms, wait_until="load")
                page.screenshot(path=path, full_page=False)
                page.close()
                captured[host] = path
            except Exception:
                pass
            if progress:
                progress(i, total)
        context.close()
        browser.close()
    return captured


def capture_screenshots(endpoints: Iterable[Endpoint], out_dir: str = SCREENSHOT_DIR,
                        timeout_ms: int = 15000,
                        progress: Callable[[int, int], None] | None = None) -> dict[str, str]:
    """Capture screenshots for live endpoints. Returns {host: local_png_path}."""
    targets = [(e.host, e.url) for e in endpoints if e.alive and e.url]
    if not targets:
        return {}
    with cf.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_capture_batch_sync, targets, out_dir, timeout_ms, progress)
        return fut.result()
