#!/usr/bin/env python3
"""
acorns_email_enum.py
--------------------
Passive OSINT email enumeration for an AUTHORIZED CTM360 security assessment.

Target domain : acorns.com
Scope         : PASSIVE ONLY. This script never sends email, never logs in, and
                never guesses passwords. It only reads public data and runs
                read-only OSINT tools.

It orchestrates (does NOT hardcode) real OSINT tooling:
  TOOL 1  theHarvester  - free CLI (subprocess), parses its JSON output.
  TOOL 2  Hunter.io     - free API (key from env var HUNTER_API_KEY).
  TOOL 3  Google dorks  - printed for manual running (can't be automated).
  FALLBACK              - derive emails from the known public naming pattern
                          for named executives the tools missed.

Output:
  - A clean terminal report.
  - CSV: acorns_email_enumeration.csv  (Name, Title, Email, Source, Format, Confidence)
"""

import csv
import json
import os
import shutil
import subprocess
import sys

try:
    import requests  # only used for the Hunter.io HTTP call
except ImportError:
    requests = None

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

TARGET = "acorns.com"
CSV_OUT = "acorns_email_enumeration.csv"
HARVESTER_PREFIX = "harvester_out"          # theHarvester -f output prefix

# The organization's naming pattern as documented by OSINT pattern databases.
# Used only as a FALLBACK for names the live tools did not return.
PATTERN_PRIMARY = "first.last"              # ~64% primary pattern for acorns.com

# Small nickname dictionary: a public first name that is likely a shortened form.
# If a person's first name is here, the derived email is less certain -> Medium.
NICKNAMES = {
    "pete": "peter",
    "liz": "elizabeth",
    "russ": "russell",
    "jamie": "james",
}

# Public names gathered passively (company About page, craft.co, public record).
# Format: (Name, Title, Source)
PUBLIC_NAMES = [
    ("Noah Kerner",       "CEO & Chairman",          "acorns.com-about"),
    ("Seth Wunder",       "Global President & CFO",   "acorns.com-about"),
    ("Kasia Leyden",      "Global CMO",               "acorns.com-about"),
    ("Denise Chisolm",    "Chief Compliance Officer", "acorns.com-about"),
    ("Daniel Wood",       "CTO",                      "acorns.com-about"),
    ("Jamie Henderson",   "Global VP Product",        "acorns.com-about"),
    ("Liz Nie",           "General Counsel",          "acorns.com-about"),
    ("Pete Johnson",      "COO",                      "acorns.com-about"),
    ("Russ Brodmerkle",   "VP Growth Marketing",      "acorns.com-about"),
    ("Imad Banna",        "CISO",                     "craft.co"),
    ("Jeff Cruttenden",   "Co-Founder",               "public-record"),
    ("Walter Cruttenden",  "Co-Founder",              "public-record"),
]

# Sources that are third-party (lower trust) -> derived emails from them = Low.
THIRD_PARTY_SOURCES = {"craft.co", "public-record"}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def banner(text):
    """Print a section banner to the terminal."""
    print("\n" + "=" * 68)
    print(text)
    print("=" * 68)


def hunter_confidence_label(score):
    """Map Hunter.io's numeric confidence (0-100) to our High/Medium/Low label."""
    if score is None:
        return "Low"
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def build_email(pattern, first, last):
    """
    Build an email local-part from a Hunter-style pattern template.

    Supported tokens: {first} {last} {f} {l}
      "{first}.{last}" + (Noah, Kerner) -> noah.kerner
      "{f}{last}"      + (Noah, Kerner) -> nkerner
    """
    local = (pattern
             .replace("{first}", first)
             .replace("{last}", last)
             .replace("{f}", first[:1])
             .replace("{l}", last[:1]))
    return f"{local}@{TARGET}"


# --------------------------------------------------------------------------- #
# TOOL 1 - theHarvester (free CLI, no API key)
# --------------------------------------------------------------------------- #

def _build_theharvester_command():
    """
    Decide how to launch theHarvester:
      1. Native binary on PATH (Linux / Kali / native Windows install), or
      2. Through WSL (Windows Subsystem for Linux) if it is installed there.
    Returns a subprocess argument list, or None if theHarvester can't be found.
    Note: 'bing' was removed as a source - theHarvester 5.x no longer supports it.
    """
    sources = "duckduckgo,crtsh,yahoo"

    # Option 1: theHarvester is directly on PATH.
    if shutil.which("theHarvester") or shutil.which("theharvester"):
        return ["theHarvester", "-d", TARGET, "-b", sources, "-f", HARVESTER_PREFIX]

    # Option 2: fall back to WSL (common on Windows). Output is written into the
    # current Windows folder via its /mnt path so this script can read the JSON.
    if shutil.which("wsl"):
        try:
            wsldir = subprocess.run(["wsl", "wslpath", "-a", os.getcwd()],
                                    capture_output=True, text=True, timeout=30).stdout.strip()
        except Exception:
            return None
        if not wsldir:
            return None
        inner = (f'cd "{wsldir}" && '
                 f'~/.local/bin/theHarvester -d {TARGET} -b {sources} -f {HARVESTER_PREFIX}')
        return ["wsl", "-d", "Ubuntu", "--", "bash", "-lc", inner]

    return None


def run_theharvester():
    """
    Run theHarvester as a subprocess and parse its JSON output for emails/hosts.

    Returns a list of result dicts. Emails from theHarvester are REAL findings,
    so Source='theHarvester' and Confidence='High'. If theHarvester cannot be
    found (native or via WSL), print a note and return [] (never crash).
    """
    banner("TOOL 1 - theHarvester (passive, read-only)")
    results = []

    cmd = _build_theharvester_command()
    if cmd is None:
        print("[!] theHarvester not found (no native binary and no WSL install).")
        print("    Install it (Linux/WSL):  git clone https://github.com/laramies/theHarvester")
        print("    then  pip install --break-system-packages -e .   Skipping this tool.")
        return results

    print("[*] Running:", " ".join(cmd))
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception as exc:
        print(f"[!] theHarvester failed to run ({type(exc).__name__}). Skipping.")
        return results

    # theHarvester writes <prefix>.json ; parse whichever JSON it produced.
    json_path = HARVESTER_PREFIX + ".json"
    if not os.path.exists(json_path):
        print(f"[!] Expected output '{json_path}' not found. Skipping.")
        return results

    try:
        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        print(f"[!] Could not parse {json_path} ({type(exc).__name__}). Skipping.")
        return results

    emails = data.get("emails", []) or []
    hosts = data.get("hosts", []) or []
    print(f"[+] theHarvester returned {len(emails)} emails and {len(hosts)} hosts.")

    for email in emails:
        email = (email or "").strip().lower()
        if email.endswith("@" + TARGET):
            results.append({
                "name": "(found by theHarvester)",
                "title": "",
                "email": email,
                "source": "theHarvester",
                "format": "(as found)",
                "confidence": "High",
            })
    return results


# --------------------------------------------------------------------------- #
# TOOL 2 - Hunter.io (free API key)
# --------------------------------------------------------------------------- #

def run_hunter():
    """
    Query the Hunter.io domain-search API for confirmed emails and the naming
    pattern. API key is read from the env var HUNTER_API_KEY (never hardcoded).

    Returns (results_list, confirmed_pattern_or_None). If no key is set or the
    request fails, print a note and return ([], None) without crashing.
    """
    banner("TOOL 2 - Hunter.io (passive domain search)")
    results = []
    pattern = None

    api_key = os.environ.get("HUNTER_API_KEY")
    if not api_key:
        print("[!] No HUNTER_API_KEY environment variable set.")
        print("    Set it first (PowerShell):  $env:HUNTER_API_KEY=\"your_key_here\"")
        print("    Then re-run this script. Skipping Hunter.io for now.")
        return results, pattern

    if requests is None:
        print("[!] The 'requests' library is not installed (pip install requests). Skipping.")
        return results, pattern

    url = "https://api.hunter.io/v2/domain-search"
    params = {"domain": TARGET, "api_key": api_key}
    print(f"[*] GET {url}?domain={TARGET}&api_key=***")
    try:
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        print(f"[!] Hunter.io request failed ({type(exc).__name__}). Skipping.")
        return results, pattern

    data = payload.get("data", {}) or {}
    pattern = data.get("pattern")          # e.g. "{first}.{last}"
    emails = data.get("emails", []) or []
    print(f"[+] Hunter.io confirmed pattern: {pattern!r}")
    print(f"[+] Hunter.io returned {len(emails)} emails.")

    for e in emails:
        value = (e.get("value") or "").strip().lower()
        if not value:
            continue
        first = e.get("first_name") or ""
        last = e.get("last_name") or ""
        name = (first + " " + last).strip() or "(no name)"
        score = e.get("confidence")
        results.append({
            "name": name,
            "title": e.get("position") or "",
            "email": value,
            "source": "Hunter.io",
            "format": pattern or PATTERN_PRIMARY,
            "confidence": hunter_confidence_label(score),
        })
    return results, pattern


# --------------------------------------------------------------------------- #
# TOOL 3 - Google dorking (manual; printed only)
# --------------------------------------------------------------------------- #

def print_google_dorks():
    """Google dorking cannot be automated politely -> print queries to run by hand."""
    banner("TOOL 3 - Google dorks (run these manually in your browser)")
    for q in (
        'site:acorns.com "@acorns.com"',
        '"@acorns.com" -site:acorns.com',
        'site:linkedin.com/in "Acorns"',
    ):
        print("   " + q)


# --------------------------------------------------------------------------- #
# FALLBACK - pattern derivation for named people the tools missed
# --------------------------------------------------------------------------- #

def derive_from_pattern(confirmed_pattern=None):
    """
    Derive emails for the public name list using the organization's pattern.

    If a live tool (Hunter.io) confirmed the real pattern, we USE that - so the
    derived guesses match the real format (e.g. {f}{last} -> nkerner@acorns.com).
    Otherwise we fall back to the documented default ({first}.{last}).

    Confidence rules:
      - Low    if the name came from a third-party source (craft.co / public-record)
      - Medium if the first name looks like a nickname (Pete, Liz, Russ, Jamie)
      - High   otherwise (clean official full name from the company's own page)
    """
    # Prefer the live-confirmed pattern; fall back to the documented default.
    pattern = confirmed_pattern if confirmed_pattern else "{first}.{last}"
    banner(f"FALLBACK - pattern derivation (pattern: {pattern})")
    results = []

    for name, title, source in PUBLIC_NAMES:
        parts = name.lower().split()
        if len(parts) < 2:
            continue
        first, last = parts[0], parts[-1]
        email = build_email(pattern, first, last)   # apply the chosen pattern

        # Decide confidence from the rules above.
        if source in THIRD_PARTY_SOURCES:
            confidence = "Low"
        elif first in NICKNAMES:
            confidence = "Medium"                # likely shortened first name
        else:
            confidence = "High"

        results.append({
            "name": name,
            "title": title,
            "email": email,
            "source": "Pattern (derived)",
            "format": pattern,
            "confidence": confidence,
        })

    print(f"[+] Derived {len(results)} candidate emails from the naming pattern.")
    return results


# --------------------------------------------------------------------------- #
# MERGE + OUTPUT
# --------------------------------------------------------------------------- #

def merge_results(tool_results, pattern_results):
    """
    Combine all sources, de-duplicating by email.

    A tool-found email (theHarvester / Hunter.io) always beats a derived one,
    so we add tool results first and only add a derived email if that address
    has not already been seen.
    """
    merged = {}
    for r in tool_results:          # higher trust first
        merged[r["email"]] = r
    for r in pattern_results:       # fill gaps only
        if r["email"] not in merged:
            merged[r["email"]] = r
    # Sort: High, then Medium, then Low; then by email for stable order.
    order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(merged.values(), key=lambda r: (order.get(r["confidence"], 9), r["email"]))


def print_report(rows, tools_ran, confirmed_pattern):
    """Print the clean terminal report."""
    banner("EMAIL ENUMERATION REPORT  -  " + TARGET)
    print("Tools that ran :", ", ".join(tools_ran) if tools_ran else "none")
    print("Confirmed format:", confirmed_pattern or f"{PATTERN_PRIMARY} (from pattern DB, unconfirmed by live tool)")
    print("-" * 68)
    for r in rows:
        who = r["name"]
        if r["title"]:
            who += f" ({r['title']})"
        print(f"[{r['confidence']:<6}] {r['email']:<34} {who}")
        print(f"          source: {r['source']}   format: {r['format']}")
    print("-" * 68)

    # Summary counts by confidence.
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in rows:
        counts[r["confidence"]] = counts.get(r["confidence"], 0) + 1
    print(f"TOTAL: {len(rows)} emails  |  High: {counts['High']}  "
          f"Medium: {counts['Medium']}  Low: {counts['Low']}")


def write_csv(rows):
    """Write the required CSV deliverable."""
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Name", "Title", "Email", "Source", "Format", "Confidence"])
        for r in rows:
            writer.writerow([r["name"], r["title"], r["email"],
                             r["source"], r["format"], r["confidence"]])
    print(f"\n[+] Wrote {len(rows)} rows to {CSV_OUT}")


# --------------------------------------------------------------------------- #
# Main orchestration
# --------------------------------------------------------------------------- #

def main():
    print("Passive email enumeration (AUTHORIZED assessment) - target:", TARGET)
    print("Scope: passive only - no email sent, no login, read-only OSINT.")

    tools_ran = []

    # TOOL 1
    harvester_results = run_theharvester()
    if harvester_results:
        tools_ran.append("theHarvester")

    # TOOL 2
    hunter_results, confirmed_pattern = run_hunter()
    if hunter_results:
        tools_ran.append("Hunter.io")

    # TOOL 3 (manual)
    print_google_dorks()

    # FALLBACK - uses Hunter's confirmed pattern when available, else the default
    pattern_results = derive_from_pattern(confirmed_pattern)

    # MERGE
    all_tool_results = harvester_results + hunter_results
    rows = merge_results(all_tool_results, pattern_results)

    # OUTPUT
    print_report(rows, tools_ran, confirmed_pattern)
    write_csv(rows)


if __name__ == "__main__":
    sys.exit(main())
