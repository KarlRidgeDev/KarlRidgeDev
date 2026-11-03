# OSINT Investigator v0.9.1

**Status:** Personal cybersecurity learning project · Desktop Python application

OSINT Investigator is a Tkinter-based workbench for researching **publicly available** information and documenting observations during authorised investigations. It focuses on traceable, preliminary findings rather than claiming that automated checks prove a vulnerability.

## What it can investigate

- **Domains and DNS:** A, AAAA, MX, NS, SOA, CAA, TXT and DS records; SPF references and DMARC policies; optional DKIM selector, MTA-STS and TLS-RPT observations.
- **Websites:** HTTPS/TLS certificate details, redirect behaviour, selected security headers, `security.txt` and `robots.txt`. Checks are limited and do not constitute a penetration test.
- **Public IP information:** Reverse DNS, prefixes and ASN information using RIPEstat.
- **Usernames:** Public GitHub and Hacker News profile leads, without assuming matching usernames identify the same person.
- **Emails:** An optional free breach-dataset lookup via [XposedOrNot](https://xposedornot.com/api_doc), requiring an ownership/permission confirmation.
- **Passwords:** A Pwned Passwords range query using a partial SHA-1 hash rather than submitting the full password.
- **Evidence and reporting:** Findings, notes, source references, an evidence graph, and exportable case reports.

## Requirements

- Python **3.9 or newer**
- Tkinter (usually included with Python on Windows; some Linux installations require `python3-tk`)
- Internet access for external lookups
- `dnspython`

## Run the application

Open a terminal in this folder and run:

```bash
python -m pip install -r requirements.txt
python main.py
```

The application opens a desktop window. Enter an authorised domain, public IP, username or email, then select **Investigate**. Email checks require ticking the account-ownership/permission checkbox. Use the notes and report features to document what was checked and what remains uncertain.

## Privacy and ethical limits

- **Only investigate public information or systems/accounts you own or have permission to examine.**
- **Email lookup sends the full email address to XposedOrNot** over HTTPS. Only use this on accounts you are authorised to check.
- The password feature sends only a five-character SHA-1 hash prefix to the Pwned Passwords service. Avoid entering passwords into unfamiliar software; a dummy password is suitable for demonstration.
- A missing security header in a single HEAD response is **not proof of a vulnerability**.
- A provider's breach match is a lead for further verification; no match is **not proof an account is safe**.
- DNS and routing data are observations, not proof of ownership, identity or a server's physical location.
- The software does not perform exploitation.

## Source code

[View the Python application](main.py) · [Dependencies](requirements.txt)

## Development notes

This is **v0.9.1** and remains a learning project. Python syntax was checked before publication, but full end-to-end checks of the GUI and external APIs have **not** been completed for this portfolio release. Service availability and provider response formats may change.

### What I learned

Building this project helped me practise OSINT, defensive network research, basic Python GUI development, reporting, responsible handling of personal data, and distinguishing preliminary findings from confirmed security issues.
