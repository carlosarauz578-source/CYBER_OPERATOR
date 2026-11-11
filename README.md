# Cyber Operator — Terminal Edition

Cyber Operator is a terminal-first intelligence search tool built on the
existing Python package. It classifies targets, selects compatible sources,
executes implemented connectors, persists search history/cache in SQLite, and
exports JSON or Markdown reports.

> DNS, RDAP, and crt.sh are wired into the engine. Other registered sources are
> metadata only and are reported as not implemented. Private and internal
> targets are blocked because the configured DNS resolver may be public. This
> project is not represented as production-ready.

## Install

Python 3.8+ and pip are required. On Kali, use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Runtime dependencies are only dnspython and requests. Tests and optional
development tooling are in `requirements-dev.txt`. Streamlit is not required
for the CLI; the old web interface is optional:

```bash
pip install -r requirements.txt -r requirements-web.txt
streamlit run cyber_operator/interface/app.py
```

## CLI use

From the project root:

```bash
python3 main.py
python3 main.py --target example.com --operation osint
python3 main.py --target example.com --operation osint --mode all
python3 main.py --target example.com --sources dns_resolver,rdap_lookup
python3 main.py --target example.com --operation web --sources crtsh
python3 main.py --list-sources
python3 main.py --list-tools
python3 main.py --history
python3 main.py --reports
python3 main.py --export QUERY_ID --format markdown
python3 main.py --target example.com --output json
```

Operations are `osint`, `network`, `web`, `threat`, `blockchain`, and `lab`.
The interactive menu also includes Source Manager, Search History, and Report
Management. Source toggles are for the current process only.

`--list-tools` checks whether Nmap, WhatWeb, Nuclei, `dig`, `host`, or
`nslookup` can be found on PATH. It does not install or execute them. The
application does not run intrusive scans.

## Sources and behavior

- DNS: domain/URL record lookup and IP reverse lookup.
- RDAP: IANA-bootstrap-selected domain lookup and IP lookup.
- crt.sh: Certificate Transparency search for domain names.
- Public lookups are not run for private/internal targets.
- `all` selects active compatible catalog sources; unimplemented sources
  appear as not implemented rather than fabricated successes.
- `recommended` selects the implemented compatible connectors.
- `manual` runs only the selected, active, compatible sources.
- Query history and per-source results are saved in
  `database/cyber_operator.db`; successful connector responses are cached with
  a one-hour TTL.

## Tests

Unit tests use controlled connector responses and do not depend on public
services:

```bash
pip install -r requirements-dev.txt
python -m pytest cyber_operator/tests -q
```

Live DNS, RDAP, and crt.sh availability varies by network and public-service
health. Those checks must be reported separately from unit tests. The code was
developed on Windows; a Kali-host startup check remains necessary.
