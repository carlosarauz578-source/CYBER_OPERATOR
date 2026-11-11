# Cyber Operator — Terminal Edition status

Updated: 2026-11-08

## CLI and runtime

- `main.py` starts the interactive terminal menu or accepts command-line arguments.
- Runtime dependencies are limited to `dnspython` and `requests`; Streamlit is
  optional and listed separately in `requirements-web.txt`.
- `--list-tools` detects Nmap, WhatWeb, Nuclei, and common DNS utilities. It
  does not invoke or install any of them.
- SQLite stores query history, per-source responses, and source-result cache
  entries subject to TTL.

## Implemented source dispatch

| Source | Query engine dispatch | Target types | Notes |
|---|---|---|---|
| DNS Resolver | A/AAAA/MX/NS lookup or reverse DNS | Domain, URL, IP | Uses dnspython/system DNS configuration. |
| RDAP Lookup | Domain registration or IP lookup | Domain, URL, IP | Domain lookup follows IANA RDAP bootstrap. |
| crt.sh | Certificate Transparency search | Domain, URL with domain host | Public endpoint may return HTTP errors or time out. |

Other registry entries are not implemented and are reported as such, rather
than returning simulated data. Network scanning is not run.

Private and internal targets are blocked before any connector runs because
the configured DNS resolver may be public; this CLI does not offer an
internal-resolver configuration yet.

## Verification

The controlled test suite is:

```bash
python -m pytest cyber_operator/tests -q
```

External lookups are separate and depend on public services and network
availability. During development, RDAP domain calls for `example.com` and
`example.org` succeeded. DNS and crt.sh responses varied between success,
timeouts, and HTTP 502 errors, so they are not guaranteed to be available.

The implementation was edited and exercised on Windows. Kali Linux was not
available in this session; Kali startup has not been demonstrated and should
be verified on a Kali host.

This status is not a production-readiness claim.
