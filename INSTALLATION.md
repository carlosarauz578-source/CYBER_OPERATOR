# Cyber Operator — Installation

## Kali Linux

The CLI uses Python 3.8+ and a small set of runtime libraries. From the
existing project directory:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py --help
python3 main.py --list-sources
python3 main.py
```

The commands above are the expected Kali workflow. The current development
session ran on Windows, so Kali execution has not yet been independently
verified.

## Windows development

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --help
```

## Optional dependencies

Install unit-test and development tools only when needed:

```bash
pip install -r requirements-dev.txt
python -m pytest cyber_operator/tests -q
```

Streamlit is optional and is not imported by the CLI:

```bash
pip install -r requirements.txt -r requirements-web.txt
streamlit run cyber_operator/interface/app.py
```

## Runtime notes

- The core search connectors are DNS, RDAP, and crt.sh.
- Private/internal targets are blocked to prevent disclosure to potentially
  public resolvers or services.
- Nmap, WhatWeb, Nuclei, and DNS utilities are only detected with
  `python3 main.py --list-tools`; Cyber Operator does not install or execute
  them.
- SQLite history, per-source results, and cache are stored under the existing
  `database/` directory.
- Other registered sources are not implemented and will not produce simulated
  data.
