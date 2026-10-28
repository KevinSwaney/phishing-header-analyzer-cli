# Phishing Header Analyzer (CLI)

## The business risk first

A single convincing email is still how most breaches start. One employee clicking one fake login page can hand over credentials, trigger a fraudulent payment, or open the door to ransomware. The cost is measured in incident response hours, customer notification, and lost trust, all from a message that took minutes to send.

This command line tool reads raw email headers and produces a one page report, so a suspicious message becomes a decision in seconds: act, verify elsewhere, or delete.

## What it flags

- **Lookalike domains:** punycode tricks, hyphen heavy names, swapped letters, and trusted brand names buried inside a different domain (for example, paypal.com.attacker.com is attacker.com, not PayPal).
- **Authentication failures:** SPF, DKIM, and DMARC reported as fail, meaning the message did not prove it came from the claimed domain.
- **Hidden rule style indicators:** urgency language, credential or payment requests, reply to mismatch, and a corporate display name sent from a free mailbox.
- **Delivery path:** an unusually short hop count for external mail.

This is a command line version with a one page report. It is distinct from the earlier email header analyzer: this one adds lookalike domain checks and the urgency and credential request signals, and formats the output as a single report.

## Run it

```bash
python phishing_analyzer.py samples/suspicious.txt
python phishing_analyzer.py --demo
cat headers.txt | python phishing_analyzer.py
```

**Getting headers:** Gmail: open the message, click the three dots, "Show original", copy everything. Outlook: File, Properties, copy "Internet headers".

## A clean report is not a clean bill of health

No single flag proves phishing, and no clean report proves a message is safe. When in doubt, verify through a second channel: type the official address yourself or use the official app, never by replying to the message.

## Requirements

Python 3.8 or later. No third party packages. Nothing leaves your machine.

## Author

Kevin Swaney, Principal Cybersecurity Engineer. More at [kevintswaney.com](https://kevintswaney.com).
