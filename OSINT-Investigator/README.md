# OSINT Investigator — v0.9 (Work in Progress)

## Overview
OSINT Investigator is a personal cybersecurity learning project focused on gathering and reporting information from public sources. The aim is to practise responsible open-source intelligence (OSINT), understand the limits of automated checks, and present findings clearly without overclaiming risk.

## Features explored so far
- Public DNS and HTTPS checks for domains and websites.
- Basic inspection of HTTP security headers, including HSTS, Content Security Policy (CSP), and `X-Content-Type-Options: nosniff`.
- Email investigation workflow with privacy-aware output.
- Clear reporting of preliminary findings, informational observations, and unavailable checks.
- Browser-based public searching as an explicit manual action rather than scraping search engines.
- An optional Have I Been Pwned (HIBP) integration, subject to authorisation and API access.

## Interpreting findings
The tool is designed to distinguish an observation from a confirmed vulnerability. For example, a security header not seen in a single HTTP HEAD response is **not** proof that a site is insecure. A check that is skipped or cannot run is **not** a clean result.

The HIBP API key has not been supplied, so automated breach lookups are currently skipped. This must not be reported as “no breaches”.

## Ethical boundaries
- Use public information and approved services, not intrusive scanning.
- Only perform account-specific breach queries for accounts I own or have authorisation to investigate.
- Avoid collecting or publishing personal information unnecessarily.
- Explain uncertainty and limitations in every report.

## Current status and next steps
**Status:** Learning project, v0.9. This page documents the work; the application source code has **not yet been added to this portfolio**.

Next steps include improving output readability, testing against known safe examples, and documenting installation and usage instructions when the source code is ready to publish.

## What I'm learning
OSINT research, security reporting, responsible data handling, interpreting web security headers, and the difference between missing evidence and evidence of a security issue.
