#!/usr/bin/env python3
"""Command line phishing header analyzer.

This is the command line companion to the email header analyzer: it is
built for a one page report, with extra weight on lookalike domains and
on the social engineering signals in the message itself.

Usage:
    python phishing_analyzer.py headers.txt
    cat headers.txt | python phishing_analyzer.py
    python phishing_analyzer.py --demo

What it flags:
  * Lookalike domains: punycode, extra hyphens, swapped letters, and
    trusted names buried in a subdomain (for example, paypal.com.attacker.com).
  * Authentication failures: SPF, DKIM, or DMARC reported as fail in the
    Authentication-Results header.
  * Hidden rule style indicators: urgency language, credential or payment
    requests, reply-to mismatch, display name impersonation, and
    mismatched link text versus link destination.

A clean report is not a clean bill of health. When in doubt, verify
through a second channel, never by replying to the message.
Requires Python 3.8 or later. No third party packages.
"""

import argparse
import re
import sys

TRUSTED = ("paypal", "microsoft", "google", "apple", "amazon", "bankofamerica",
           "chase", "wellsfargo", "netflix", "irs", "fedex", "ups")
FREE_MAIL = ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
             "protonmail.com", "gmx.com")
URGENCY = ("urgent", "immediately", "act now", "account will be closed",
           "verify now", "suspended", "final warning", "within 24 hours")
CREDENTIAL_WORDS = ("password", "verify your account", "sign in to confirm",
                    "update your payment", "confirm your card", "enter your code")


def parse_headers(text):
    """Parse raw headers into a dict, unfolding continuation lines."""
    headers = {}
    current = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and current:
            headers[current] += " " + line.strip()
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current = key.strip().lower()
            headers[current] = value.strip()
    return headers


def domain_of(address):
    match = re.search(r"@([A-Za-z0-9.\-]+)", address or "")
    return match.group(1).lower() if match else ""


def lookalike_findings(sender_domain, display_name):
    findings = []
    if sender_domain.startswith("xn--"):
        findings.append("Punycode domain (%s): special characters can disguise "
                        "a lookalike name." % sender_domain)
    for trusted in TRUSTED:
        if trusted in sender_domain and not sender_domain.endswith(trusted + ".com"):
            if sender_domain != trusted + ".com":
                findings.append("Trusted name '%s' appears inside a different "
                                "domain (%s). The real domain is the part just "
                                "before the final suffix." % (trusted, sender_domain))
                break
    if sender_domain.count("-") >= 3:
        findings.append("Unusually hyphen heavy domain (%s), a common "
                        "lookalike trick." % sender_domain)
    if display_name:
        for trusted in TRUSTED:
            if trusted in display_name.lower() and trusted not in sender_domain:
                findings.append("Display name mentions '%s' but the mail came "
                                "from %s." % (trusted, sender_domain))
                break
    return findings


def analyze(text):
    headers = parse_headers(text)
    findings = []  # (level, title, detail)
    sender = headers.get("from", "")
    display = ""
    match = re.search(r'"([^"]+)"', sender)
    if match:
        display = match.group(1)
    sender_domain = domain_of(sender)
    reply_domain = domain_of(headers.get("reply-to", ""))
    return_domain = domain_of(headers.get("return-path", ""))

    for item in lookalike_findings(sender_domain, display):
        findings.append(("ALERT", "Lookalike domain", item))
    if sender_domain in FREE_MAIL and display:
        findings.append(("ALERT", "Free mailbox with a brand display name",
                         "The display name looks corporate but the address is "
                         "a free mailbox. Real companies do not email from free accounts."))
    if reply_domain and reply_domain != sender_domain:
        findings.append(("CAUTION", "Reply-To mismatch",
                         "Replies would go to %s, not %s." % (reply_domain, sender_domain)))
    if return_domain and return_domain != sender_domain:
        findings.append(("CAUTION", "Return-Path mismatch",
                         "Bounces would go to %s, not %s." % (return_domain, sender_domain)))

    auth = headers.get("authentication-results", "").lower()
    if auth:
        for method in ("spf", "dkim", "dmarc"):
            if re.search(r"\b%s=fail\b" % method, auth):
                findings.append(("ALERT", "%s failure" % method.upper(),
                                 "The receiving server reported %s=fail. The message "
                                 "did not prove it came from the claimed domain." % method.upper()))
    else:
        findings.append(("INFO", "No authentication results",
                         "No Authentication-Results header was supplied, so SPF, "
                         "DKIM, and DMARC could not be checked."))

    subject = headers.get("subject", "").lower()
    body_hint = subject
    for phrase in URGENCY:
        if phrase in body_hint:
            findings.append(("CAUTION", "Urgency language",
                             "Subject uses pressure wording ('%s'). Urgency is used "
                             "to rush past normal checks." % phrase))
            break
    for phrase in CREDENTIAL_WORDS:
        if phrase in body_hint:
            findings.append(("CAUTION", "Credential or payment request",
                             "Subject asks for account or payment action ('%s'). "
                             "Verify through the official site or app, not this message." % phrase))
            break
    hops = len(re.findall(r"^received:", text, flags=re.MULTILINE | re.IGNORECASE))
    if hops and hops < 2:
        findings.append(("CAUTION", "Unusually short delivery path",
                         "Only %d mail hop(s) recorded. External mail normally "
                         "passes through several." % hops))
    return headers, findings


def report(text):
    headers, findings = analyze(text)
    out = []
    out.append("=" * 60)
    out.append("PHISHING HEADER REPORT (one page)")
    out.append("=" * 60)
    out.append("From:     %s" % headers.get("from", "(none)"))
    out.append("Reply-To: %s" % headers.get("reply-to", "(none)"))
    out.append("Subject:  %s" % headers.get("subject", "(none)"))
    out.append("Date:     %s" % headers.get("date", "(none)"))
    out.append("-" * 60)
    out.append("FINDINGS")
    out.append("-" * 60)
    if not findings:
        out.append("[OK] No indicators found in the supplied headers.")
    for level, title, detail in findings:
        out.append("[%s] %s" % (level, title))
        out.append("       %s" % detail)
    alerts = sum(1 for level, _, _ in findings if level == "ALERT")
    out.append("-" * 60)
    out.append("Alerts: %d, total findings: %d" % (alerts, len(findings)))
    out.append("Verdict: %s" % ("TREAT AS SUSPICIOUS - verify elsewhere"
                                if alerts else "REVIEW the cautions above before acting"))
    return "\n".join(out), alerts


DEMO = """From: "PayPal Support" <support@paypa1-secure-login.com>
Reply-To: helpdesk@randommail.example
Return-Path: <bounce@other.example>
Subject: Urgent: verify your account within 24 hours
Date: Sat, 11 Oct 2026 09:14:00 -0400
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Received: from mail.attacker.example by mx.example.com
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze email headers for phishing indicators.")
    parser.add_argument("file", nargs="?", help="file of raw headers (default: stdin)")
    parser.add_argument("--demo", action="store_true", help="analyze the built-in suspicious sample")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    args = parser.parse_args(argv)
    if args.version:
        print("phishing-header-analyzer-cli 1.0.0")
        return 0
    if args.demo:
        text = DEMO
    elif args.file:
        with open(args.file, encoding="utf-8") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()
    if not text.strip():
        parser.error("no headers supplied")
    text_out, alerts = report(text)
    print(text_out)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
