
"""OSINT Investigator v0.9.1 — free OSINT workbench.

Requirements:
    python -m pip install dnspython

Features:
    Domain, DNS, email security, website security,
    IP intelligence, username lookup, free email
    breach checking, private password checking,
    evidence graph, case reports and analyst notes.

Public information and authorised investigations only.
"""

import hashlib
import html
import http.client
import ipaddress
import json
import math
import os
import queue
import re
import socket
import ssl
import threading
import tkinter as tk
import webbrowser

from datetime import datetime, timezone
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from urllib.parse import quote, urlencode, urljoin, urlsplit

import dns.exception
import dns.resolver
import dns.reversename


# ==========================================
# APPLICATION SETTINGS
# ==========================================

APP = "OSINT Investigator v0.9.1"

BG = "#101827"
PANEL = "#0f172a"
INPUT = "#1e293b"
TEXT = "#e2e8f0"
MUTED = "#94a3b8"
BLUE = "#0284c7"

TABS = (
    "Overview",
    "DNS",
    "Email",
    "Website",
    "IP",
    "Identity",
    "Graph",
    "Findings",
    "Notes"
)

AGENT = (
    "OSINT-Investigator/0.9.1 "
    "(personal defensive research)"
)

XON_DOC = "https://xposedornot.com/api_doc"


# ==========================================
# INPUT VALIDATION
# ==========================================

def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")


def validate_domain(value, dns_reference=False):

    value = value.strip().lower().rstrip(".")

    if not value or any(
        c in value for c in "/:@\\ ?#"
    ):
        raise ValueError(
            "Enter a domain name, not a URL"
        )

    try:
        value = value.encode(
            "idna"
        ).decode("ascii")

    except UnicodeError as exc:
        raise ValueError(
            "Invalid domain name"
        ) from exc

    if dns_reference:
        pattern = (
            r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?"
        )
    else:
        pattern = (
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
        )

    labels = value.split(".")

    if (
        len(value) > 253
        or len(labels) < 2
        or any(
            len(label) > 63
            or not re.fullmatch(pattern, label)
            for label in labels
        )
    ):
        raise ValueError(
            "Invalid domain name"
        )

    return value


def validate_email(value):

    value = value.strip()

    if (
        len(value) > 254
        or not re.fullmatch(
            r"[^\s@<>]{1,64}@[^\s@<>]+",
            value
        )
    ):
        raise ValueError(
            "Enter a valid email address"
        )

    local, domain = value.rsplit(
        "@", 1
    )

    return (
        local + "@" +
        validate_domain(domain)
    )


def mask_email(value):

    local, domain = value.rsplit(
        "@", 1
    )

    return (
        local[:1] +
        "***@" +
        domain
    )


def classify(value, selected="Auto"):

    value = value.strip()

    if selected == "Auto":

        if "@" in value:
            selected = "Email"

        else:
            try:
                ipaddress.ip_address(value)
                selected = "IP"

            except ValueError:
                selected = (
                    "Domain"
                    if "." in value
                    else "Username"
                )

    if selected == "Email":
        return selected, validate_email(value)

    if selected == "Domain":
        return selected, validate_domain(value)

    if selected == "IP":

        address = ipaddress.ip_address(value)

        if not address.is_global:
            raise ValueError(
                "Only public IP addresses are accepted"
            )

        return selected, str(address)

    if selected == "Username":

        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}",
            value
        ):
            raise ValueError(
                "Username must contain 1-39 "
                "letters, numbers, '-' or '_'"
            )

        return selected, value

    raise ValueError(
        "Unknown target type"
    )


# ==========================================
# VERIFIED HTTPS CONNECTIONS
# ==========================================

def public_addresses(host):

    records = socket.getaddrinfo(
        host,
        443,
        type=socket.SOCK_STREAM
    )

    addresses = {
        record[4][0]
        for record in records
    }

    if not addresses or not all(
        ipaddress.ip_address(ip).is_global
        for ip in addresses
    ):
        raise ValueError(
            "HTTPS host resolves to a "
            "non-public IP address"
        )

    return sorted(
        addresses,
        key=lambda ip: (":" in ip, ip)
    )[:8]


class PinnedHTTPS(http.client.HTTPSConnection):

    def __init__(self, host, ip):

        super().__init__(
            host,
            port=443,
            timeout=8,
            context=ssl.create_default_context()
        )

        self.ip = ip

    def connect(self):

        raw = socket.create_connection(
            (self.ip, 443),
            timeout=self.timeout
        )

        try:
            self.sock = self._context.wrap_socket(
                raw,
                server_hostname=self.host
            )

        except BaseException:
            raw.close()
            raise


def https(
    url,
    method="GET",
    limit=160000,
    extra_headers=None
):

    parsed = urlsplit(url)

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        raise ValueError(
            "Only HTTPS on port 443 is allowed"
        )

    host = validate_domain(
        parsed.hostname
    )

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    failure = None

    for ip in public_addresses(host):

        connection = PinnedHTTPS(
            host,
            ip
        )

        try:
            connection.connect()

            cert = connection.sock.getpeercert()
            tls = connection.sock.version()
            cipher = connection.sock.cipher()[0]

            headers = {
                "User-Agent": AGENT,
                "Accept-Encoding": "identity",
                "Connection": "close"
            }

            headers.update(
                extra_headers or {}
            )

            connection.request(
                method,
                path,
                headers=headers
            )

            response = connection.getresponse()

            if method == "GET":
                body = response.read(
                    limit + 1
                )
            else:
                body = b""

            if len(body) > limit:
                raise ValueError(
                    "Remote response too large"
                )

            return {
                "status": response.status,
                "body": body,
                "url": url,
                "ip": ip,
                "headers": {
                    k.lower(): v
                    for k, v in response.getheaders()
                },
                "cert": cert,
                "tls": tls,
                "cipher": cipher
            }

        except ssl.SSLCertVerificationError:
            raise

        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException
        ) as exc:
            failure = exc

        finally:
            connection.close()

    raise OSError(
        "HTTPS request failed: " +
        str(failure)
    )


def json_https(
    url,
    limit=160000,
    headers=None
):

    response = https(
        url,
        "GET",
        limit,
        headers
    )

    if response["status"] != 200:
        return None, response["status"]

    return (
        json.loads(
            response["body"].decode("utf-8")
        ),
        200
    )


def follow_https(url):

    seen = set()
    hops = []

    for index in range(4):

        if url in seen:
            return hops, "Redirect loop"

        seen.add(url)

        reply = https(
            url,
            "HEAD"
        )

        hops.append(reply)

        if reply["status"] not in (
            301, 302, 303, 307, 308
        ):
            return hops, None

        location = reply[
            "headers"
        ].get("location")

        if not location or index == 3:
            return hops, "Redirect limit reached"

        url = urljoin(
            url,
            location
        )

        parsed = urlsplit(url)

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
            or parsed.port not in (None, 443)
        ):
            return hops, "Unsafe redirect blocked"

        validate_domain(
            parsed.hostname
        )

    return hops, "Redirect limit reached"


# ==========================================
# FREE EMAIL BREACH CHECKER
# ==========================================

def free_breach_lookup(email):

    url = (
        "https://api.xposedornot.com/"
        "v1/check-email/" +
        quote(email, safe="")
    )

    data, status = json_https(url)

    if status == 404:
        return [], "NO_MATCH"

    if status == 429:
        return [], "RATE_LIMIT"

    if status != 200:
        raise ValueError(
            f"XposedOrNot returned HTTP {status}"
        )

    if not isinstance(data, dict):
        raise ValueError(
            "Unexpected API response"
        )

    if str(
        data.get("Error", "")
    ).lower() == "not found":
        return [], "NO_MATCH"

    values = data.get("breaches")

    if not isinstance(values, list):
        raise ValueError(
            "API did not return a breach list"
        )

    names = []

    for group in values:

        entries = (
            group
            if isinstance(group, list)
            else [group]
        )

        for entry in entries:

            if isinstance(entry, str):

                name = " ".join(
                    entry.split()
                )[:90]

                if name and name not in names:
                    names.append(name)

    if names:
        return names, "FOUND"

    return [], "NO_MATCH"


# ==========================================
# PASSWORD EXPOSURE CHECKER
# ==========================================

def check_password_hash(sha1_digest):

    if not re.fullmatch(
        r"[0-9A-F]{40}",
        sha1_digest
    ):
        raise ValueError(
            "Invalid password digest"
        )

    url = (
        "https://api.pwnedpasswords.com/"
        "range/" +
        sha1_digest[:5]
    )

    response = https(
        url,
        limit=1100000,
        extra_headers={
            "Add-Padding": "true"
        }
    )

    if response["status"] != 200:
        raise ValueError(
            "Password service returned HTTP " +
            str(response["status"])
        )

    suffix = sha1_digest[5:]

    lines = response[
        "body"
    ].decode(
        "ascii",
        "replace"
    ).splitlines()

    for line in lines:

        check, separator, count = (
            line.partition(":")
        )

        if (
            separator
            and check.upper() == suffix
        ):
            return int(count.strip())

    return 0


# ==========================================
# INVESTIGATION CASE
# ==========================================

class Case:

    def __init__(
        self,
        kind,
        target,
        selector=""
    ):

        self.kind = kind
        self.target = target

        self.display = (
            mask_email(target)
            if kind == "Email"
            else target
        )

        self.selector = selector
        self.timestamp = utc_now()

        self.sections = {
            name: []
            for name in TABS
        }

        self.findings = []
        self.nodes = []
        self.edges = []
        self.sources = []

        self.notes = ""
        self.partial = False
        self.cancelled = False

        self.node(
            "target",
            self.display,
            kind,
            "target"
        )

    def log(self, section, text=""):

        self.sections[section].append(
            str(text)
        )

    def finding(
        self,
        level,
        title,
        explanation,
        source=""
    ):

        item = {
            "level": level,
            "title": title,
            "evidence": explanation,
            "source": source
        }

        if item not in self.findings:
            self.findings.append(item)

    def node(
        self,
        ident,
        label,
        kind,
        certainty="observed"
    ):

        if not any(
            n["id"] == ident
            for n in self.nodes
        ):

            self.nodes.append({
                "id": ident,
                "label": label,
                "kind": kind,
                "certainty": certainty
            })

    def link(
        self,
        a,
        b,
        description,
        certainty="observed"
    ):

        edge = {
            "from": a,
            "to": b,
            "label": description,
            "certainty": certainty
        }

        if edge not in self.edges:
            self.edges.append(edge)

    def source(self, name, location):

        self.sources.append({
            "name": name,
            "location": location,
            "checked": utc_now()
        })

    def export(self):

        return {
            "application": APP,
            "type": self.kind,
            "target": self.display,
            "timestamp": self.timestamp,
            "partial": self.partial,
            "cancelled": self.cancelled,
            "selector": self.selector,
            "sections": {
                k: "\n".join(v)
                for k, v in self.sections.items()
            },
            "findings": self.findings,
            "nodes": self.nodes,
            "edges": self.edges,
            "sources": self.sources,
            "notes": self.notes,
            "limitations": (
                "Provider reports are leads, "
                "not identity proof or "
                "confirmed vulnerabilities."
            )
        }


# ==========================================
# INVESTIGATION ENGINE
# ==========================================

class Engine:

    def __init__(
        self,
        case,
        cancel,
        progress
    ):

        self.c = case
        self.cancel = cancel
        self.progress = progress

        self.resolver = dns.resolver.Resolver()

        self.resolver.timeout = 2
        self.resolver.lifetime = 5

        self.dns_cache = {}
        self.spf_count = 0

    def check(self):

        if self.cancel.is_set():
            raise InterruptedError(
                "Investigation cancelled"
            )

    # ======================================
    # DNS LOOKUPS
    # ======================================

    def records(self, domain, kind):

        self.check()

        key = (
            domain.lower(),
            kind.upper()
        )

        if key in self.dns_cache:
            return self.dns_cache[key]

        try:
            answer = self.resolver.resolve(
                domain,
                kind,
                raise_on_no_answer=False
            )

            if answer.rrset:
                result = list(answer), None
            else:
                result = [], "No record"

        except dns.resolver.NXDOMAIN:
            result = [], "Name does not exist"

        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ) as exc:

            self.c.partial = True

            result = [], type(exc).__name__

        except dns.exception.DNSException as exc:

            self.c.partial = True

            result = [], "DNS error: " + str(exc)

        self.dns_cache[key] = result

        return result

    def txt(self, domain):

        records, error = self.records(
            domain,
            "TXT"
        )

        return [
            b"".join(
                r.strings
            ).decode(
                "utf-8",
                "replace"
            )
            for r in records
        ], error

    # ======================================
    # DNS INTELLIGENCE
    # ======================================

    def run_dns(self):

        c = self.c
        domain = c.target

        c.log(
            "DNS",
            "PUBLIC DNS INTELLIGENCE — " +
            domain
        )

        for kind in (
            "A", "AAAA", "MX", "NS",
            "SOA", "CAA", "TXT", "DS"
        ):

            items, error = self.records(
                domain,
                kind
            )

            c.log(
                "DNS",
                f"\n[{kind}] {error or ''}"
            )

            for record in items[:35]:

                c.log(
                    "DNS",
                    record.to_text()[:1200]
                )

            if kind in ("A", "AAAA"):

                for item in items[:12]:

                    ident = (
                        "ip:" + item.address
                    )

                    c.node(
                        ident,
                        item.address,
                        "IP"
                    )

                    c.link(
                        "target",
                        ident,
                        kind + " record"
                    )

        c.source(
            "Public DNS answers",
            "Local DNS resolver"
        )

        c.log(
            "DNS",
            "\nDNSSEC validation and zone "
            "transfer are not performed."
        )

    # ======================================
    # SPF ANALYSIS
    # ======================================

    def spf(
        self,
        domain,
        depth=0,
        parents=None
    ):

        parents = parents or set()
        prefix = "  " * depth

        if domain in parents:

            self.c.finding(
                "REVIEW",
                "SPF circular reference",
                domain
            )

            self.c.log(
                "Email",
                prefix + "SPF circular reference"
            )
            return

        if depth > 5 or self.spf_count >= 10:

            self.c.partial = True

            self.c.log(
                "Email",
                prefix + "SPF inspection cap reached"
            )
            return

        self.spf_count += 1

        texts, error = self.txt(domain)

        policies = [
            t for t in texts
            if re.match(
                r"^v=spf1(?:\s|$)",
                t,
                re.I
            )
        ]

        self.c.log(
            "Email",
            prefix + domain + " SPF: " +
            (error or " | ".join(policies))
        )

        if len(policies) > 1:

            self.c.finding(
                "REVIEW",
                "Multiple SPF policies",
                domain
            )
            return

        if len(policies) != 1:
            return

        tokens = policies[0].split()[1:]

        for token in tokens:

            low = token.lower()

            if low in ("all", "+all"):

                self.c.finding(
                    "REVIEW",
                    "Permissive SPF all",
                    domain
                )

            if low.lstrip("+-~?").startswith(
                "include:"
            ):
                kind = "include"

            elif low.startswith("redirect="):
                kind = "redirect"

            else:
                continue

            separator = (
                ":"
                if kind == "include"
                else "="
            )

            ref = token.split(
                separator,
                1
            )[1]

            self.c.log(
                "Email",
                prefix + f"  {kind} → {ref}"
            )

            if kind == "redirect":

                all_mechanisms = (
                    "all", "+all", "-all",
                    "~all", "?all"
                )

                if any(
                    t.lower() in all_mechanisms
                    for t in tokens
                ):
                    continue

            if "%" in ref:

                self.c.partial = True

                self.c.log(
                    "Email",
                    prefix + "  Macros not evaluated"
                )
                continue

            try:
                target = validate_domain(
                    ref,
                    dns_reference=True
                )

                self.spf(
                    target,
                    depth + 1,
                    parents | {domain}
                )

            except ValueError:

                self.c.partial = True

                self.c.log(
                    "Email",
                    prefix + "  Invalid reference"
                )

    # ======================================
    # EMAIL SECURITY
    # ======================================

    def run_email(self):

        c = self.c
        domain = c.target

        c.log(
            "Email",
            f"MAIL CONFIGURATION — {domain}\n"
        )

        mx, error = self.records(
            domain,
            "MX"
        )

        c.log(
            "Email",
            "MX: " +
            (
                error or
                ", ".join(
                    r.to_text()
                    for r in mx
                )
            )
        )

        if (
            len(mx) == 1
            and mx[0].preference == 0
            and str(mx[0].exchange) == "."
        ):
            c.finding(
                "INFO",
                "Null MX",
                "Incoming mail intentionally disabled"
            )

        c.log(
            "Email",
            "\nSPF POLICY AND REFERENCES"
        )

        self.spf(domain)

        c.log(
            "Email",
            f"Inspected {self.spf_count}/10 SPF "
            "TXT policies; not full evaluation."
        )

        dmarc, error = self.txt(
            "_dmarc." + domain
        )

        policies = [
            r for r in dmarc
            if re.match(
                r"^v=DMARC1(?:\s*;|$)",
                r
            )
        ]

        c.log(
            "Email",
            "\nDMARC: " +
            (
                error or
                " | ".join(policies) or
                "No policy observed"
            )
        )

        if len(policies) > 1:

            c.finding(
                "REVIEW",
                "Multiple DMARC records",
                domain
            )

        elif len(policies) == 1:

            tags = {}

            for part in policies[0].split(";"):

                if "=" in part:

                    key, value = part.strip().split(
                        "=",
                        1
                    )

                    tags[key.strip()] = value.strip()

            p = tags.get(
                "p",
                "missing"
            ).lower()

            sp = tags.get(
                "sp",
                p
            ).lower()

            c.log(
                "Email",
                f"Main p={p}; subdomain sp={sp}"
            )

            c.log(
                "Email",
                "Alignment SPF=" +
                tags.get("aspf", "r") +
                " DKIM=" +
                tags.get("adkim", "r")
            )

            if p == "none":

                c.finding(
                    "INFO",
                    "DMARC monitoring only",
                    "Published p=none"
                )

            allowed = (
                "none",
                "quarantine",
                "reject"
            )

            if p not in allowed or sp not in allowed:

                c.finding(
                    "REVIEW",
                    "DMARC policy needs review",
                    policies[0]
                )

        if c.selector:

            name = (
                c.selector +
                "._domainkey." +
                domain
            )

            keys, error = self.txt(name)

            c.log(
                "Email",
                "\nDKIM " + name + ": " +
                (
                    error or
                    " | ".join(keys[:2])[:1500]
                )
            )

        else:

            c.log(
                "Email",
                "\nDKIM not checked: "
                "selector not supplied"
            )

        sts, error = self.txt(
            "_mta-sts." + domain
        )

        c.log(
            "Email",
            "\nMTA-STS: " +
            (
                error or
                " | ".join(sts)
            )
        )

        if any(
            r.startswith("v=STSv1")
            for r in sts
        ):

            url = (
                f"https://mta-sts.{domain}"
                "/.well-known/mta-sts.txt"
            )

            try:
                response = https(
                    url,
                    limit=18000
                )

                c.log(
                    "Email",
                    "MTA-STS HTTPS: " +
                    str(response["status"])
                )

                if response["status"] == 200:

                    policy = response[
                        "body"
                    ].decode(
                        "utf-8",
                        "replace"
                    )

                    c.log(
                        "Email",
                        policy[:4000]
                    )

                    c.source(
                        "MTA-STS policy",
                        url
                    )

                else:
                    c.partial = True

            except (
                OSError,
                ValueError,
                ssl.SSLError
            ) as exc:

                c.partial = True

                c.log(
                    "Email",
                    "MTA-STS incomplete: " +
                    str(exc)
                )

        rpt, error = self.txt(
            "_smtp._tls." + domain
        )

        c.log(
            "Email",
            "\nTLS-RPT: " +
            (
                error or
                " | ".join(rpt)
            )
        )

        c.log(
            "Email",
            "\nThese are published DNS policies, "
            "not proof of successful email "
            "authentication."
        )

    # ======================================
    # WEBSITE SECURITY
    # ======================================

    def run_website(self):

        c = self.c

        c.log(
            "Website",
            "HTTPS SECURITY REVIEW — " +
            c.target
        )

        try:
            hops, error = follow_https(
                "https://" + c.target + "/"
            )

        except (
            OSError,
            ValueError,
            ssl.SSLError
        ) as exc:

            c.partial = True

            c.log(
                "Website",
                "TLS/HTTPS check incomplete: " +
                str(exc)
            )
            return

        for hop in hops:

            c.log(
                "Website",
                f"{hop['status']} "
                f"{hop['url']} "
                f"({hop['ip']})"
            )

            if hop["status"] in (
                301, 302, 303, 307, 308
            ):

                c.log(
                    "Website",
                    "Location: " +
                    hop["headers"].get(
                        "location",
                        "not given"
                    )
                )

        if error:

            c.partial = True

            c.log(
                "Website",
                error
            )
            return

        final = hops[-1]

        c.source(
            "Final HTTPS HEAD response",
            final["url"]
        )

        c.log(
            "Website",
            f"\nTLS: {final['tls']}"
            f" | Cipher: {final['cipher']}"
        )

        cert = final["cert"]

        c.log(
            "Website",
            "Issuer: " +
            str(
                cert.get(
                    "issuer",
                    "unknown"
                )
            )
        )

        c.log(
            "Website",
            "Expiry: " +
            str(
                cert.get(
                    "notAfter",
                    "unknown"
                )
            )
        )

        if cert.get("notAfter"):

            try:
                expiry = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(
                        cert["notAfter"]
                    ),
                    timezone.utc
                )

                remaining = (
                    expiry -
                    datetime.now(timezone.utc)
                ).days

                if remaining < 30:

                    c.finding(
                        "REVIEW",
                        "Certificate approaching expiry",
                        f"{remaining} days",
                        final["url"]
                    )

            except ValueError:
                c.partial = True

        headers = final["headers"]

        c.log(
            "Website",
            "\nSECURITY HEADERS "
            "(one HEAD response)"
        )

        names = (
            "server",
            "content-type",
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-frame-options"
        )

        for name in names:

            c.log(
                "Website",
                f"{name}: " +
                headers.get(
                    name,
                    "not observed"
                )
            )

        if final["status"] == 200:

            if (
                "strict-transport-security"
                not in headers
            ):

                c.finding(
                    "REVIEW",
                    "HSTS not observed",
                    "One HEAD response; "
                    "preload not checked",
                    final["url"]
                )

            if (
                "content-security-policy"
                not in headers
            ):

                c.finding(
                    "INFO",
                    "CSP not observed",
                    "One HEAD response",
                    final["url"]
                )

            if headers.get(
                "x-content-type-options",
                ""
            ).lower() != "nosniff":

                c.finding(
                    "INFO",
                    "nosniff not observed",
                    "One HEAD response",
                    final["url"]
                )

        host = validate_domain(
            urlsplit(
                final["url"]
            ).hostname
        )

        for path in (
            "/.well-known/security.txt",
            "/robots.txt"
        ):

            self.check()

            url = (
                "https://" +
                host +
                path
            )

            try:
                reply = https(
                    url,
                    "GET",
                    12000
                )

                c.log(
                    "Website",
                    f"\n{path}: HTTP "
                    f"{reply['status']}"
                )

                if reply["status"] == 200:

                    content = reply[
                        "body"
                    ].decode(
                        "utf-8",
                        "replace"
                    )

                    c.log(
                        "Website",
                        content[:2400]
                    )

                    c.source(
                        "Public website metadata",
                        url
                    )

            except (
                OSError,
                ValueError,
                ssl.SSLError
            ) as exc:

                c.log(
                    "Website",
                    path + " not retrieved: " +
                    str(exc)[:160]
                )

        c.log(
            "Website",
            "\nObservations are not "
            "confirmed vulnerabilities."
        )

    # ======================================
    # IP AND ASN INTELLIGENCE
    # ======================================

    def run_ip(self):

        c = self.c

        if c.kind == "IP":
            addresses = [c.target]

        else:
            addresses = []

            for kind in ("A", "AAAA"):

                records, error = self.records(
                    c.target,
                    kind
                )

                for record in records:

                    if ipaddress.ip_address(
                        record.address
                    ).is_global:

                        addresses.append(
                            record.address
                        )

        addresses = list(
            dict.fromkeys(addresses)
        )

        c.log(
            "IP",
            "NETWORK INTELLIGENCE — "
            "IP / ASN / REVERSE DNS"
        )

        if not addresses:

            c.log(
                "IP",
                "No public IP addresses returned"
            )
            return

        ipv4 = [
            a for a in addresses
            if ":" not in a
        ][:2]

        ipv6 = [
            a for a in addresses
            if ":" in a
        ][:2]

        chosen = ipv4 + ipv6

        c.log(
            "IP",
            "Addresses: " +
            ", ".join(addresses)
        )

        for address in chosen:

            self.check()

            ident = "ip:" + address

            c.node(
                ident,
                address,
                "IP"
            )

            if c.kind == "Domain":

                c.link(
                    "target",
                    ident,
                    "A/AAAA DNS answer"
                )

            c.log(
                "IP",
                "\nIP: " + address
            )

            reverse = (
                dns.reversename.from_address(
                    address
                )
            )

            ptr, error = self.records(
                str(reverse),
                "PTR"
            )

            c.log(
                "IP",
                "PTR: " +
                (
                    error or
                    ", ".join(
                        str(r.target)
                        for r in ptr
                    )
                )
            )

            url = (
                "https://stat.ripe.net/data/"
                "network-info/data.json?" +
                urlencode({
                    "resource": address
                })
            )

            try:
                result, status = json_https(url)

                if (
                    status != 200
                    or not isinstance(
                        result,
                        dict
                    )
                    or result.get("status") != "ok"
                ):
                    raise ValueError(
                        "RIPEstat network information "
                        "unavailable"
                    )

                info = result.get(
                    "data"
                ) or {}

                c.log(
                    "IP",
                    "Routing prefix: " +
                    str(
                        info.get(
                            "prefix",
                            "unknown"
                        )
                    )
                )

                c.source(
                    "RIPEstat network info",
                    url
                )

                asns = info.get(
                    "asns"
                ) or []

                for raw in asns[:2]:

                    asn = (
                        "AS" +
                        str(raw).removeprefix("AS")
                    )

                    overview_url = (
                        "https://stat.ripe.net/data/"
                        "as-overview/data.json?" +
                        urlencode({
                            "resource": asn
                        })
                    )

                    overview, status = json_https(
                        overview_url
                    )

                    if (
                        status != 200
                        or not isinstance(
                            overview,
                            dict
                        )
                    ):
                        raise ValueError(
                            "RIPEstat ASN overview "
                            "unavailable"
                        )

                    holder = str(
                        (
                            overview.get("data") or {}
                        ).get(
                            "holder",
                            "not reported"
                        )
                    )

                    c.log(
                        "IP",
                        f"{asn}: {holder}"
                    )

                    c.source(
                        "RIPEstat AS overview",
                        overview_url
                    )

                    c.node(
                        "asn:" + asn,
                        asn + " " + holder[:20],
                        "ASN",
                        "routing observation"
                    )

                    c.link(
                        ident,
                        "asn:" + asn,
                        "BGP origin observation"
                    )

            except (
                OSError,
                ValueError,
                ssl.SSLError,
                json.JSONDecodeError
            ) as exc:

                c.partial = True

                c.log(
                    "IP",
                    "RIPEstat incomplete: " +
                    str(exc)[:200]
                )

        c.log(
            "IP",
            "\nRouting holder does not prove "
            "the server's physical location."
        )

    # ======================================
    # IDENTITY INTELLIGENCE
    # ======================================

    def run_identity(self):

        c = self.c

        c.log(
            "Identity",
            "IDENTITY INTELLIGENCE — " +
            c.display
        )

        # ----------------------------------
        # FREE EMAIL BREACH LOOKUP
        # ----------------------------------

        if c.kind == "Email":

            c.log(
                "Identity",
                "\nProvider: XposedOrNot"
            )

            c.log(
                "Identity",
                "FREE BREACH SEARCH — "
                "NO API KEY REQUIRED"
            )

            c.log(
                "Identity",
                "The full email address is sent "
                "to XposedOrNot over HTTPS "
                "with your permission."
            )

            c.log(
                "Identity",
                "\nChecking provider dataset..."
            )

            try:
                names, status = free_breach_lookup(
                    c.target
                )

                c.source(
                    "XposedOrNot free breach API",
                    XON_DOC
                )

                if status == "RATE_LIMIT":

                    c.partial = True

                    c.log(
                        "Identity",
                        "\nRATE LIMITED (HTTP 429)"
                    )

                    c.log(
                        "Identity",
                        "Result unknown. Try later."
                    )

                elif status == "NO_MATCH":

                    c.log(
                        "Identity",
                        "\nNO MATCH FOUND"
                    )

                    c.log(
                        "Identity",
                        "The provider found no "
                        "matching exposure in "
                        "its breach dataset."
                    )

                    c.log(
                        "Identity",
                        "This does not prove "
                        "the account is safe."
                    )

                else:
                    c.log(
                        "Identity",
                        "\nEXPOSURE REPORTED"
                    )

                    c.log(
                        "Identity",
                        f"{len(names)} unique "
                        "breach names returned."
                    )

                    for name in names[:50]:

                        c.log(
                            "Identity",
                            "• " + name
                        )

                        ident = (
                            "breach:" + name
                        )

                        c.node(
                            ident,
                            name,
                            "Breach",
                            "provider claim"
                        )

                        c.link(
                            "target",
                            ident,
                            "provider-reported breach",
                            "provider claim"
                        )

                    if len(names) > 50:

                        c.log(
                            "Identity",
                            f"... {len(names) - 50} "
                            "additional entries "
                            "not displayed"
                        )

                    c.finding(
                        "REVIEW",
                        "Email exposure reported",
                        "XposedOrNot listed " +
                        str(len(names)) +
                        " breach names. "
                        "Verify independently.",
                        XON_DOC
                    )

                    c.log(
                        "Identity",
                        "\nNo leaked passwords or "
                        "credentials were retrieved."
                    )

            except (
                OSError,
                ValueError,
                ssl.SSLError,
                json.JSONDecodeError
            ) as exc:

                c.partial = True

                c.log(
                    "Identity",
                    "\nBREACH CHECK INCOMPLETE"
                )

                c.log(
                    "Identity",
                    str(exc)[:240]
                )

                c.log(
                    "Identity",
                    "This is not a negative result."
                )

        # ----------------------------------
        # PUBLIC USERNAME SEARCH
        # ----------------------------------

        elif c.kind == "Username":

            username = c.target

            c.log(
                "Identity",
                "\nPublic username matches "
                "are leads, not proof that "
                "accounts belong to one person."
            )

            services = [
                (
                    "GitHub",
                    "https://api.github.com/users/" +
                    quote(username, safe="")
                ),
                (
                    "Hacker News",
                    "https://hacker-news.firebaseio.com/"
                    "v0/user/" +
                    quote(username, safe="") +
                    ".json"
                )
            ]

            for service, url in services:

                self.check()

                try:
                    data, status = json_https(url)

                    if status == 404 or data is None:

                        c.log(
                            "Identity",
                            service +
                            ": no public profile returned"
                        )
                        continue

                    if (
                        status != 200
                        or not isinstance(
                            data,
                            dict
                        )
                    ):
                        raise ValueError(
                            "HTTP " + str(status)
                        )

                    if service == "GitHub":

                        profile = str(
                            data.get("html_url")
                            or (
                                "https://github.com/" +
                                quote(
                                    username,
                                    safe=""
                                )
                            )
                        )

                        details = (
                            "display name=" +
                            str(
                                data.get("name")
                                or "not public"
                            ) +
                            ", public repos=" +
                            str(
                                data.get(
                                    "public_repos",
                                    "unknown"
                                )
                            )
                        )

                    else:

                        profile = (
                            "https://news.ycombinator.com/"
                            "user?id=" +
                            quote(username, safe="")
                        )

                        details = (
                            "public karma=" +
                            str(
                                data.get(
                                    "karma",
                                    "unknown"
                                )
                            )
                        )

                    c.log(
                        "Identity",
                        f"\n{service}: "
                        "MATCHING PUBLIC USERNAME"
                    )

                    c.log(
                        "Identity",
                        "Profile: " + profile
                    )

                    c.log(
                        "Identity",
                        details
                    )

                    ident = (
                        "profile:" + service
                    )

                    c.node(
                        ident,
                        service + " / " + username,
                        "Public profile",
                        "unverified lead"
                    )

                    c.link(
                        "target",
                        ident,
                        "same username; "
                        "identity unverified",
                        "lead"
                    )

                    c.source(
                        service + " public profile",
                        profile
                    )

                except (
                    OSError,
                    ValueError,
                    ssl.SSLError,
                    json.JSONDecodeError
                ) as exc:

                    c.partial = True

                    c.log(
                        "Identity",
                        service +
                        ": lookup inconclusive: " +
                        str(exc)[:150]
                    )

            c.log(
                "Identity",
                "\nUse PUBLIC SEARCH for "
                "manual searches on other platforms."
            )

    # ======================================
    # RUN ALL REQUIRED MODULES
    # ======================================

    def run(self):

        c = self.c

        c.log(
            "Overview",
            APP + " — " + c.timestamp
        )

        c.log(
            "Overview",
            "Target: " + c.display +
            " | Type: " + c.kind
        )

        c.log(
            "Overview",
            "Public DNS, verified HTTPS, "
            "official provider APIs"
        )

        if c.kind == "Domain":

            tasks = [
                ("DNS", self.run_dns),
                ("Email", self.run_email),
                ("Website", self.run_website),
                ("IP", self.run_ip)
            ]

        elif c.kind == "IP":

            tasks = [
                ("IP", self.run_ip)
            ]

        else:

            tasks = [
                ("Identity", self.run_identity)
            ]

        for name, task in tasks:

            try:
                self.check()

                self.progress(
                    "Investigating " + name + "..."
                )

                task()

            except InterruptedError:

                c.cancelled = True
                c.partial = True

                c.log(
                    name,
                    "Cancelled; partial results preserved"
                )
                break

            except Exception as exc:

                c.partial = True

                c.log(
                    name,
                    "Module incomplete: " +
                    type(exc).__name__ +
                    ": " + str(exc)
                )

        if c.cancelled:
            status = "CANCELLED"

        elif c.partial:
            status = "PARTIAL"

        else:
            status = "FINISHED"

        c.log(
            "Overview",
            "Status: " + status
        )

        c.log(
            "Overview",
            "Preliminary findings: " +
            str(len(c.findings))
        )

        if c.kind == "Email":

            c.log(
                "Overview",
                "Email breach results come "
                "from XposedOrNot, not HIBP."
            )

        c.log(
            "Overview",
            "A missing result is not proof "
            "of safety. No exploitation performed."
        )

        c.log(
            "Findings",
            "PRELIMINARY FINDINGS — "
            "not confirmed vulnerabilities"
        )

        if not c.findings:

            c.log(
                "Findings",
                "No flagged findings. Review "
                "module logs for negative "
                "or incomplete checks."
            )

        for item in c.findings:

            c.log(
                "Findings",
                f"[{item['level']}] "
                f"{item['title']}: "
                f"{item['evidence']}"
            )

        return c


# ==========================================
# REPORT EXPORT
# ==========================================

def case_text(data):

    lines = [
        data["application"],
        "Target: " + data["target"],
        "Time: " + data["timestamp"]
    ]

    for tab in TABS:

        content = data[
            "sections"
        ].get(tab)

        if content:

            lines.extend([
                "\n" + "=" * 58,
                tab.upper(),
                content
            ])

    lines.append("\nSOURCES")

    for item in data["sources"]:

        lines.append(
            item["name"] +
            ": " +
            item["location"]
        )

    lines.extend([
        "\nANALYST NOTES",
        data["notes"],
        "\n" + data["limitations"]
    ])

    return "\n".join(lines)


def case_html(data):

    body = ""

    for name in TABS:

        content = data[
            "sections"
        ].get(name, "")

        if not content:
            continue

        body += (
            "<section><h2>" +
            html.escape(name) +
            "</h2><pre>" +
            html.escape(content) +
            "</pre></section>"
        )

    sources = ""

    for item in data["sources"]:

        sources += (
            "<li>" +
            html.escape(item["name"]) +
            ": " +
            html.escape(item["location"]) +
            "</li>"
        )

    return (
        "<!doctype html>"
        "<html><head>"
        "<meta charset='utf-8'>"
        "<title>OSINT Case</title>"
        "<style>"
        "body{background:#101827;"
        "color:#e2e8f0;"
        "font:16px system-ui;"
        "max-width:1100px;"
        "margin:30px auto;padding:20px}"
        "section{background:#1e293b;"
        "padding:15px;margin:15px 0;"
        "border-radius:10px}"
        "pre{white-space:pre-wrap;"
        "overflow-wrap:anywhere}"
        "h1,h2{color:#38bdf8}"
        "</style></head><body>"
        "<h1>OSINT Investigator</h1>"
        "<p>" +
        html.escape(data["target"]) +
        "</p>" +
        body +
        "<h2>Sources</h2><ul>" +
        sources +
        "</ul>"
        "<h2>Analyst notes</h2><pre>" +
        html.escape(data["notes"]) +
        "</pre>"
        "<p>" +
        html.escape(data["limitations"]) +
        "</p></body></html>"
    )


# ==========================================
# TKINTER APPLICATION
# ==========================================

class App:

    def __init__(self, root):

        self.root = root

        root.title(APP)
        root.geometry("1230x790")
        root.minsize(890, 580)
        root.configure(bg=BG)

        self.jobs = queue.Queue()
        self.cancel = threading.Event()

        self.busy = False
        self.case = None

        style = ttk.Style(root)
        style.theme_use("clam")

        style.configure(
            "TNotebook",
            background=BG
        )

        style.configure(
            "TNotebook.Tab",
            background=INPUT,
            foreground=TEXT,
            padding=(10, 8)
        )

        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", BLUE)
            ]
        )

        # ----------------------------------
        # HEADER
        # ----------------------------------

        tk.Label(
            root,
            text="OSINT INVESTIGATOR",
            font=("Segoe UI", 23, "bold"),
            bg=BG,
            fg="#38bdf8"
        ).pack(
            anchor="w",
            padx=18,
            pady=(12, 0)
        )

        tk.Label(
            root,
            text=(
                "FREE breach searches • Email • "
                "DNS • Website • IP • Evidence graph"
            ),
            bg=BG,
            fg=MUTED
        ).pack(
            anchor="w",
            padx=19,
            pady=(0, 10)
        )

        # ----------------------------------
        # UNIVERSAL SEARCH
        # ----------------------------------

        row = tk.Frame(
            root,
            bg=BG
        )

        row.pack(
            fill="x",
            padx=18
        )

        self.target = self.entry(
            row,
            47
        )

        self.target.insert(
            0,
            "example.com"
        )

        self.target.pack(
            side="left",
            padx=(0, 9)
        )

        self.kind = ttk.Combobox(
            row,
            state="readonly",
            width=14,
            values=(
                "Auto",
                "Email",
                "Username",
                "Domain",
                "IP"
            )
        )

        self.kind.set("Auto")

        self.kind.pack(
            side="left",
            padx=(0, 9)
        )

        self.selector = self.entry(
            row,
            15
        )

        self.selector.pack(
            side="left",
            padx=(0, 6)
        )

        tk.Label(
            row,
            text="DKIM selector",
            bg=BG,
            fg=MUTED
        ).pack(side="left")

        # ----------------------------------
        # EMAIL PERMISSION
        # ----------------------------------

        auth_row = tk.Frame(
            root,
            bg=BG
        )

        auth_row.pack(
            fill="x",
            padx=18,
            pady=(5, 0)
        )

        self.authorised = tk.BooleanVar(
            value=False
        )

        tk.Checkbutton(
            auth_row,
            text=(
                "For email: I own this account "
                "or have permission to check it"
            ),
            variable=self.authorised,
            bg=BG,
            fg=TEXT,
            selectcolor=INPUT,
            activebackground=BG,
            activeforeground=TEXT
        ).pack(side="left")

        tk.Label(
            auth_row,
            text=(
                "Full email sent to XposedOrNot"
            ),
            bg=BG,
            fg=MUTED
        ).pack(
            side="left",
            padx=10
        )

        # ----------------------------------
        # ACTION BUTTONS
        # ----------------------------------

        actions = tk.Frame(
            root,
            bg=BG
        )

        actions.pack(
            fill="x",
            padx=18,
            pady=9
        )

        self.go_btn = self.button(
            actions,
            "INVESTIGATE",
            self.start,
            BLUE
        )

        self.cancel_btn = self.button(
            actions,
            "CANCEL",
            self.stop,
            "#475569"
        )

        self.cancel_btn.config(
            state="disabled"
        )

        self.button(
            actions,
            "PUBLIC SEARCH",
            self.public_search,
            "#334155"
        )

        self.button(
            actions,
            "SAVE CASE",
            self.save_case,
            "#334155"
        )

        self.button(
            actions,
            "OPEN CASE",
            self.open_case,
            "#334155"
        )

        # ----------------------------------
        # TABS
        # ----------------------------------

        self.notebook = ttk.Notebook(root)

        self.notebook.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=(0, 7)
        )

        self.pages = {}
        self.views = {}

        for tab in TABS:

            page = tk.Frame(
                self.notebook,
                bg=PANEL
            )

            self.pages[tab] = page

            self.notebook.add(
                page,
                text=tab
            )

            if tab not in (
                "Graph",
                "Notes"
            ):

                widget = ScrolledText(
                    page,
                    bg=PANEL,
                    fg=TEXT,
                    insertbackground=TEXT,
                    font=("Consolas", 10),
                    wrap="word",
                    padx=12,
                    pady=12,
                    relief="flat",
                    state="disabled"
                )

                widget.pack(
                    fill="both",
                    expand=True
                )

                self.views[tab] = widget

        # ----------------------------------
        # EVIDENCE GRAPH
        # ----------------------------------

        self.canvas = tk.Canvas(
            self.pages["Graph"],
            bg=PANEL,
            highlightthickness=0
        )

        self.canvas.pack(
            fill="both",
            expand=True
        )

        self.canvas.bind(
            "<Configure>",
            lambda event: self.draw_graph()
        )

        # ----------------------------------
        # ANALYST NOTES
        # ----------------------------------

        tk.Label(
            self.pages["Notes"],
            text=(
                "Analyst notes — saved with case. "
                "Avoid sensitive information."
            ),
            bg=PANEL,
            fg=TEXT
        ).pack(
            anchor="w",
            padx=12,
            pady=8
        )

        self.notes = ScrolledText(
            self.pages["Notes"],
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            wrap="word",
            font=("Segoe UI", 11)
        )

        self.notes.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=8
        )

        # ----------------------------------
        # PASSWORD CHECKER
        # ----------------------------------

        bottom = tk.Frame(
            root,
            bg=BG
        )

        bottom.pack(
            fill="x",
            padx=18,
            pady=(0, 7)
        )

        tk.Label(
            bottom,
            text=(
                "Free private password-exposure check:"
            ),
            bg=BG,
            fg=MUTED
        ).pack(side="left")

        self.password = self.entry(
            bottom,
            22,
            hidden=True
        )

        self.password.pack(
            side="left",
            padx=8
        )

        self.pass_btn = self.button(
            bottom,
            "CHECK PASSWORD",
            self.password_check,
            "#6d28d9"
        )

        # ----------------------------------
        # STATUS
        # ----------------------------------

        self.status = tk.StringVar(
            value=(
                "Ready — choose a target "
                "and investigate"
            )
        )

        tk.Label(
            root,
            textvariable=self.status,
            bg=BG,
            fg=MUTED,
            anchor="w"
        ).pack(
            fill="x",
            padx=18,
            pady=(0, 8)
        )

        root.after(
            120,
            self.poll
        )

    # ======================================
    # INTERFACE HELPERS
    # ======================================

    @staticmethod
    def entry(
        parent,
        width,
        hidden=False
    ):

        return tk.Entry(
            parent,
            width=width,
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Segoe UI", 11),
            show="•" if hidden else ""
        )

    @staticmethod
    def button(
        parent,
        label,
        callback,
        color
    ):

        btn = tk.Button(
            parent,
            text=label,
            command=callback,
            bg=color,
            fg="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=8
        )

        btn.pack(
            side="left",
            padx=(0, 7)
        )

        return btn

    def set_text(self, tab, content):

        widget = self.views[tab]

        widget.config(
            state="normal"
        )

        widget.delete(
            "1.0",
            tk.END
        )

        widget.insert(
            tk.END,
            content
        )

        widget.config(
            state="disabled"
        )

    # ======================================
    # START INVESTIGATION
    # ======================================

    def start(self):

        if self.busy:
            return

        try:
            kind, target = classify(
                self.target.get(),
                self.kind.get()
            )

            selector = (
                self.selector.get()
                .strip()
                .lower()
            )

            if selector and not re.fullmatch(
                r"[a-z0-9_][a-z0-9_-]{0,62}",
                selector
            ):
                raise ValueError(
                    "Invalid DKIM selector"
                )

            if (
                kind == "Email"
                and not self.authorised.get()
            ):
                raise ValueError(
                    "Tick the ownership/permission "
                    "checkbox for email checks"
                )

        except ValueError as exc:

            messagebox.showwarning(
                "Check search",
                str(exc)
            )
            return

        self.busy = True

        self.cancel.clear()
        self.case = None

        self.notes.delete(
            "1.0",
            tk.END
        )

        self.go_btn.config(
            state="disabled"
        )

        self.pass_btn.config(
            state="disabled"
        )

        self.cancel_btn.config(
            state="normal"
        )

        for tab in self.views:

            self.set_text(
                tab,
                (
                    "Investigation started..."
                    if tab == "Overview"
                    else ""
                )
            )

        self.canvas.delete("all")

        self.status.set(
            "Starting " +
            kind +
            " investigation..."
        )

        def work():

            try:
                case = Engine(
                    Case(
                        kind,
                        target,
                        selector
                    ),
                    self.cancel,
                    lambda value: self.jobs.put(
                        ("status", value)
                    )
                ).run()

                self.jobs.put(
                    ("case", case)
                )

            except Exception as exc:

                self.jobs.put((
                    "error",
                    type(exc).__name__ +
                    ": " + str(exc)
                ))

        threading.Thread(
            target=work,
            daemon=True
        ).start()

    # ======================================
    # CANCEL
    # ======================================

    def stop(self):

        if self.busy:

            self.cancel.set()

            self.status.set(
                "Cancellation requested..."
            )

    # ======================================
    # REVERSE PUBLIC SEARCH
    # ======================================

    def public_search(self):

        try:
            kind, target = classify(
                self.target.get(),
                self.kind.get()
            )

            if (
                kind == "Email"
                and not self.authorised.get()
            ):
                raise ValueError(
                    "Tick the permission checkbox "
                    "before searching an email"
                )

        except ValueError as exc:

            messagebox.showwarning(
                "Public search",
                str(exc)
            )
            return

        if kind in (
            "Email",
            "Username"
        ):
            query = '"' + target + '"'

        else:
            query = target

        url = (
            "https://www.google.com/search?" +
            urlencode({
                "q": query
            })
        )

        webbrowser.open(url)

        self.status.set(
            "Public web search opened; "
            "results require verification"
        )

    # ======================================
    # PRIVATE PASSWORD CHECK
    # ======================================

    def password_check(self):

        if self.busy:
            return

        secret = self.password.get()

        self.password.delete(
            0,
            tk.END
        )

        if not secret:

            messagebox.showwarning(
                "Password check",
                "Enter a dummy test password "
                "or your own password"
            )
            return

        digest = hashlib.sha1(
            secret.encode("utf-8")
        ).hexdigest().upper()

        del secret

        self.busy = True

        self.go_btn.config(
            state="disabled"
        )

        self.pass_btn.config(
            state="disabled"
        )

        self.status.set(
            "Checking a partial SHA-1 hash; "
            "no plaintext sent..."
        )

        def work():

            try:
                count = check_password_hash(
                    digest
                )

                if count:

                    msg = (
                        "EXPOSED: This password "
                        f"appears {count:,} times "
                        "in the dataset. Change it "
                        "wherever used."
                    )

                else:

                    msg = (
                        "No dataset match found. "
                        "This does not prove the "
                        "password is secure."
                    )

            except Exception as exc:

                msg = (
                    "Password check INCOMPLETE: " +
                    str(exc)
                )

            self.jobs.put(
                ("password", msg)
            )

        threading.Thread(
            target=work,
            daemon=True
        ).start()

    # ======================================
    # SAVE CASE
    # ======================================

    def save_case(self):

        if self.busy or self.case is None:

            messagebox.showinfo(
                "Save case",
                "Finish an investigation first"
            )
            return

        self.case.notes = self.notes.get(
            "1.0",
            tk.END
        ).strip()

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON case", "*.json"),
                ("HTML report", "*.html"),
                ("Text report", "*.txt")
            ]
        )

        if not path:
            return

        data = self.case.export()

        if path.lower().endswith(".json"):

            content = json.dumps(
                data,
                indent=2,
                ensure_ascii=False
            )

        elif path.lower().endswith(".html"):

            content = case_html(data)

        else:

            content = case_text(data)

        try:
            with open(
                path,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(content)

            messagebox.showinfo(
                "Save case",
                "Saved successfully"
            )

        except OSError as exc:

            messagebox.showerror(
                "Save error",
                str(exc)
            )

    # ======================================
    # OPEN CASE
    # ======================================

    def open_case(self):

        if self.busy:
            return

        path = filedialog.askopenfilename(
            filetypes=[
                ("OSINT JSON case", "*.json")
            ]
        )

        if not path:
            return

        try:
            if os.path.getsize(path) > 2000000:
                raise ValueError(
                    "Case file exceeds 2 MB"
                )

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if (
                not isinstance(data, dict)
                or data.get("application") != APP
                or not isinstance(
                    data.get("sections"),
                    dict
                )
            ):
                raise ValueError(
                    "Not a v0.9.1 JSON case"
                )

            case = Case(
                data.get("type", "Unknown"),
                data.get("target", "Unknown"),
                data.get("selector", "")
            )

            case.display = str(
                data.get(
                    "target",
                    "Unknown"
                )
            )

            case.timestamp = data.get(
                "timestamp",
                utc_now()
            )

            case.sections = {
                k: str(
                    data["sections"].get(k, "")
                ).splitlines()
                for k in TABS
            }

            case.findings = data.get(
                "findings",
                []
            )[:150]

            case.nodes = data.get(
                "nodes",
                []
            )[:150]

            case.edges = data.get(
                "edges",
                []
            )[:250]

            case.sources = data.get(
                "sources",
                []
            )[:150]

            case.partial = bool(
                data.get(
                    "partial",
                    False
                )
            )

            case.cancelled = bool(
                data.get(
                    "cancelled",
                    False
                )
            )

            case.notes = str(
                data.get(
                    "notes",
                    ""
                )
            )[:200000]

            self.case = case

            self.notes.delete(
                "1.0",
                tk.END
            )

            self.notes.insert(
                tk.END,
                case.notes
            )

            self.show_case()

        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError
        ) as exc:

            messagebox.showerror(
                "Open case",
                str(exc)
            )

    # ======================================
    # DISPLAY CASE
    # ======================================

    def show_case(self):

        if not self.case:
            return

        content = self.case.export()

        for tab in self.views:

            self.set_text(
                tab,
                content["sections"].get(
                    tab,
                    ""
                )
            )

        self.draw_graph()

        self.notebook.select(
            self.pages["Overview"]
        )

        if self.case.partial:
            state = "PARTIAL"
        else:
            state = "FINISHED"

        self.status.set(
            state +
            " — " +
            str(len(self.case.findings)) +
            " preliminary findings"
        )

    # ======================================
    # EVIDENCE GRAPH
    # ======================================

    def draw_graph(self):

        canvas = self.canvas

        canvas.delete("all")

        if not self.case or not self.case.nodes:

            canvas.create_text(
                15,
                15,
                anchor="nw",
                fill=MUTED,
                text=(
                    "Run an investigation "
                    "to see the evidence graph"
                )
            )
            return

        nodes = self.case.nodes[:26]

        width = max(
            canvas.winfo_width(),
            760
        )

        height = max(
            canvas.winfo_height(),
            340
        )

        center = (
            width // 2,
            height // 2
        )

        positions = {
            "target": center
        }

        others = [
            n for n in nodes
            if n.get("id") != "target"
        ]

        for i, node in enumerate(others):

            angle = (
                2 * math.pi * i /
                max(len(others), 1) -
                math.pi / 2
            )

            x = center[0] + int(
                min(
                    width * 0.32,
                    290
                ) * math.cos(angle)
            )

            y = center[1] + int(
                min(
                    height * 0.34,
                    170
                ) * math.sin(angle)
            )

            positions[node["id"]] = (
                x,
                y
            )

        for edge in self.case.edges:

            a = positions.get(
                edge.get("from")
            )

            b = positions.get(
                edge.get("to")
            )

            if a and b:

                if edge.get(
                    "certainty"
                ) != "observed":

                    dashed = (4, 4)

                else:
                    dashed = ()

                canvas.create_line(
                    *a,
                    *b,
                    fill="#64748b",
                    width=2,
                    dash=dashed
                )

        for node in nodes:

            x, y = positions[node["id"]]

            if node["id"] == "target":
                color = "#166534"

            elif node.get("certainty") in (
                "provider claim",
                "unverified lead"
            ):
                color = "#92400e"

            else:
                color = BLUE

            canvas.create_rectangle(
                x - 82,
                y - 20,
                x + 82,
                y + 20,
                fill=color,
                outline=""
            )

            label = str(
                node.get(
                    "label",
                    ""
                )
            )

            if len(label) > 24:
                label = label[:24] + "…"

            canvas.create_text(
                x,
                y,
                fill="white",
                font=("Segoe UI", 9),
                text=label
            )

        canvas.create_text(
            12,
            12,
            anchor="nw",
            fill=MUTED,
            text=(
                "Dashed lines = unverified leads "
                "or provider claims"
            )
        )

    # ======================================
    # PROCESS BACKGROUND RESULTS
    # ======================================

    def poll(self):

        try:
            while True:

                action, value = (
                    self.jobs.get_nowait()
                )

                if action == "status":

                    self.status.set(value)

                elif action == "case":

                    self.case = value
                    self.busy = False

                    self.go_btn.config(
                        state="normal"
                    )

                    self.pass_btn.config(
                        state="normal"
                    )

                    self.cancel_btn.config(
                        state="disabled"
                    )

                    self.show_case()

                elif action == "password":

                    self.busy = False

                    self.go_btn.config(
                        state="normal"
                    )

                    self.pass_btn.config(
                        state="normal"
                    )

                    self.status.set(value)

                    messagebox.showinfo(
                        "Private password check",
                        value
                    )

                elif action == "error":

                    self.busy = False

                    self.go_btn.config(
                        state="normal"
                    )

                    self.pass_btn.config(
                        state="normal"
                    )

                    self.cancel_btn.config(
                        state="disabled"
                    )

                    self.status.set(
                        "Error: " + value
                    )

                    messagebox.showerror(
                        "Investigation error",
                        value
                    )

        except queue.Empty:
            pass

        self.root.after(
            120,
            self.poll
        )


# ==========================================
# LAUNCH APPLICATION
# ==========================================

def main():

    root = tk.Tk()

    App(root)

    root.mainloop()


if __name__ == "__main__":
    main()
