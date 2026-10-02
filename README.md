# Passive Recon Toolkit

Two passive OSINT tools for authorized security assessments. Passive only — no email
sent, no login, no intrusive scanning.

## Install
```bash
pip install -r requirements.txt
```

## 1. SubRecon — subdomain & web asset discovery
Finds subdomains and profiles the live web assets of a domain (dashboard).
```bash
python -m streamlit run app.py
```

## 2. MailRecon — email enumeration
Finds public corporate emails for a domain and identifies the email format.
```bash
# add your free Hunter.io key first (never hardcoded):
#   PowerShell:  $env:HUNTER_API_KEY="your_key"
python acorns_email_enum.py                  # command line
python -m streamlit run email_enum_app.py    # web UI
```

> Authorized use only. See `.env.example` for the Hunter.io key setup.
