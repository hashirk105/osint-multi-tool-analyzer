# OSINT Multi-Tool Website Analyzer

Desktop GUI (Python / Tkinter) that analyses a target website with **five OSINT tools via their APIs** (all taken from *Labs OSINT Lecture 1*, sections 1.2.3-1.2.4),
shows the results side by side in a comparison table, and exports everything to **Excel (.xlsx)**.

| # | Tool | Endpoint used | Gives |
|---|------|---------------|-------|
| 1 | VirusTotal v3 | `GET /domains/{d}`, `/domains/{d}/subdomains` | engine verdicts, reputation, registrar, creation date, subdomains |
| 2 | Shodan | `GET /shodan/host/{ip}` | open ports, services, CVEs, organisation, ASN, country |
| 3 | AbuseIPDB v2 | `GET /check?ipAddress=` | abuse-confidence score, report count, ISP, usage type |
| 4 | IPinfo | `GET /{ip}/json` | ASN, organisation, reverse DNS, city/region/country |
| 5 | GreyNoise (Community) | `GET /v3/community/{ip}` | internet-noise / benign-service (RIOT) classification |

All queries are **passive**: the target is never contacted; only the APIs above (and your DNS resolver) are.

## Run
```bash
git clone <your-repo-url> && cd osint-multi-tool-analyzer
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Requires Python 3.9+ with Tkinter (bundled on Windows/macOS; Linux: `sudo apt install python3-tk`).

1. Open **API Keys**, paste your keys (or copy `.env.example` to `.env` and fill it in).
2. Enter a domain or URL (e.g. `example.com`) and click **Analyze**.
3. Review the **Comparison Table** (double-click a row for full values), then **Export to Excel**.

Free-tier keys work, but some endpoints may be restricted ; the tool then reports the error instead of failing.

## Excel output
`Comparison` (attributes x tools) · `Findings` (filterable long format) · `Coverage` (which tool returned what) · `Raw JSON` · `Metadata`.

## Tests
`python -m unittest discover -s tests -v` (offline, HTTP mocked).

## Swapping tools
Each provider is one function in `osint_core.py` returning normalised fields; add or replace one (e.g. Censys or DomainTools from the lecture) and register it in the `PROVIDERS` dict - the GUI and Excel export adapt automatically.

## Ethics
Use only for authorised / lawful research. Never commit `.env` (already in `.gitignore`).
