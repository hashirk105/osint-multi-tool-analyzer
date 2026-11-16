"""
osint_core.py - provider clients + normalisation for the OSINT Multi-Tool Website Analyzer.

Five tools from "Labs OSINT Lecture 1" (sections 1.2.3 / 1.2.4), each needing its own API key:
    1. VirusTotal     (API v3)
    2. Shodan         (REST API)
    3. AbuseIPDB      (API v2)
    4. IPinfo         (REST API)
    5. GreyNoise      (Community API v3)

All lookups are PASSIVE: the target site is never contacted. Only the third-party
APIs (and your DNS resolver, to resolve the domain to IPs) receive traffic.

Every provider returns the same normalised structure so results can be compared
side by side:
    {"tool", "status", "message", "fields": {FIELD: value}, "raw": <json>}

Missing fields are reported as "N/A" (the tool does not provide that data type),
which is itself a meaningful result in the comparison.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlparse

import requests

TIMEOUT = 30
NA = "N/A"

# Order of the rows in the comparison table
FIELDS = [
    "Resolved IPs",
    "Reverse DNS / Hostnames",
    "Organization / ISP / Registrar",
    "ASN",
    "Reputation / Verdict",
    "Abuse reports",
    "Open ports",
    "Known vulnerabilities (CVEs)",
    "Subdomains found",
    "Server / Technologies",
    "Domain creation date",
    "Countries / Geo",
]

STATUS_OK, STATUS_ERROR, STATUS_NOKEY = "OK", "ERROR", "NO API KEY"


# --------------------------------------------------------------------------- helpers
def normalise_target(raw: str) -> str:
    """Accept 'https://www.example.com/path?x=1' or 'example.com' -> 'www.example.com'."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter a target website or domain.")
    if "://" not in raw:
        raw = "http://" + raw
    host = urlparse(raw).hostname
    if not host or "." not in host:
        raise ValueError(f"'{raw}' is not a valid domain.")
    return host.lower().rstrip(".")


def registrable_domain(host: str) -> str:
    """Naive apex-domain guess (last two labels; three for common 2-level TLDs)."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({i[4][0] for i in infos if ":" not in i[4][0]})  # IPv4 only
    except socket.gaierror:
        return []


def _fmt_list(items, limit=15) -> str:
    items = [str(i) for i in items if i not in (None, "")]
    if not items:
        return NA
    shown = sorted(set(items), key=lambda x: (len(x), x))
    extra = f" (+{len(shown) - limit} more)" if len(shown) > limit else ""
    return ", ".join(shown[:limit]) + extra


def _ts(epoch) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return NA


def _result(tool, status, message="", fields=None, raw=None):
    f = {k: NA for k in FIELDS}
    f.update(fields or {})
    return {"tool": tool, "status": status, "message": message, "fields": f, "raw": raw}


def _http_error(tool, resp) -> dict:
    hints = {
        401: "Invalid API key (401).",
        403: "Access denied (403) - key invalid or plan does not include this endpoint.",
        404: "No data found for this target (404).",
        429: "Rate limit / quota exceeded (429). Try again later.",
    }
    msg = hints.get(resp.status_code, f"HTTP {resp.status_code}")
    try:
        detail = resp.json()
        detail = detail.get("error") or detail.get("message") or detail.get("errors") or ""
        if detail:
            msg += f" Server said: {str(detail)[:150]}"
    except ValueError:
        pass
    return _result(tool, STATUS_ERROR, msg)


# --------------------------------------------------------------------------- providers
def virustotal(host: str, domain: str, ips: list[str], key: str) -> dict:
    tool = "VirusTotal"
    r = requests.get(f"https://www.virustotal.com/api/v3/domains/{host}",
                     headers={"x-apikey": key}, timeout=TIMEOUT)
    if r.status_code != 200:
        return _http_error(tool, r)
    data = r.json()
    a = data.get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    total = sum(stats.values()) or 0
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    verdict = (f"{mal} malicious / {sus} suspicious of {total} engines "
               f"(community reputation {a.get('reputation', 0)})")
    dns = a.get("last_dns_records", [])
    a_ips = [d["value"] for d in dns if d.get("type") == "A"]
    cats = a.get("categories", {})
    tags = a.get("tags", [])
    subs = NA
    try:  # optional second call; failure must not break the main result
        rs = requests.get(f"https://www.virustotal.com/api/v3/domains/{host}/subdomains",
                          params={"limit": 40}, headers={"x-apikey": key}, timeout=TIMEOUT)
        if rs.status_code == 200:
            sd = rs.json()
            data["_subdomains"] = sd
            names = [x.get("id") for x in sd.get("data", [])]
            total = sd.get("meta", {}).get("count", len(names))
            subs = f"{total}: " + _fmt_list(names, 10) if names else "0"
        else:
            subs = f"unavailable ({rs.status_code})"
    except requests.exceptions.RequestException:
        subs = "unavailable (network error)"
    return _result(tool, STATUS_OK, fields={
        "Subdomains found": subs,
        "Resolved IPs": _fmt_list(a_ips),
        "Organization / ISP / Registrar": a.get("registrar") or NA,
        "Reputation / Verdict": verdict,
        "Server / Technologies": _fmt_list(list(set(cats.values())) + tags) if (cats or tags) else NA,
        "Domain creation date": _ts(a.get("creation_date")),
    }, raw=data)


def shodan(host: str, domain: str, ips: list[str], key: str) -> dict:
    tool = "Shodan"
    if not ips:
        return _result(tool, STATUS_ERROR, "Domain did not resolve to an IPv4 address.")
    ports, vulns, orgs, products, countries, asns, hosts, raw = set(), set(), set(), set(), set(), set(), set(), {}
    last_err = None
    for ip in ips[:5]:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": key}, timeout=TIMEOUT)
        if r.status_code == 404:
            raw[ip] = "no information"
            continue
        if r.status_code != 200:
            last_err = _http_error(tool, r)
            if r.status_code in (401, 403, 429):
                break
            continue
        d = r.json()
        raw[ip] = d
        ports.update(d.get("ports", []))
        vulns.update(d.get("vulns", []))
        if d.get("org"):
            orgs.add(d["org"])
        if d.get("country_name"):
            countries.add(d["country_name"])
        if d.get("asn"):
            asns.add(d["asn"])
        hosts.update(d.get("hostnames", []))
        for svc in d.get("data", []):
            if svc.get("product"):
                products.add(f"{svc['product']} {svc.get('version', '')}".strip())
    if not raw or (last_err and not any(isinstance(v, dict) for v in raw.values())):
        return last_err or _result(tool, STATUS_OK, "Shodan has no data for these IPs.", raw=raw)
    return _result(tool, STATUS_OK, fields={
        "Resolved IPs": _fmt_list(ips),
        "Organization / ISP / Registrar": _fmt_list(orgs),
        "Open ports": _fmt_list(sorted(ports), 30),
        "Known vulnerabilities (CVEs)": _fmt_list(vulns) if vulns else "None reported",
        "Server / Technologies": _fmt_list(products),
        "Countries / Geo": _fmt_list(countries),
        "ASN": _fmt_list(asns),
        "Reverse DNS / Hostnames": _fmt_list(hosts, 8),
    }, raw=raw)


def abuseipdb(host: str, domain: str, ips: list[str], key: str) -> dict:
    tool = "AbuseIPDB"
    if not ips:
        return _result(tool, STATUS_ERROR, "Domain did not resolve to an IPv4 address.")
    raw, rows, last_err = {}, [], None
    for ip in ips[:5]:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": ip, "maxAgeInDays": 90},
                         headers={"Key": key, "Accept": "application/json"}, timeout=TIMEOUT)
        if r.status_code != 200:
            last_err = _http_error(tool, r)
            if r.status_code in (401, 403, 422, 429):
                break
            continue
        d = r.json().get("data", {})
        raw[ip] = d
        rows.append(d)
    if not rows:
        return last_err or _result(tool, STATUS_OK, "No data returned.", raw=raw)
    scores = [f"{x['ipAddress']}: {x.get('abuseConfidenceScore', 0)}% confidence" for x in rows]
    reports = [f"{x['ipAddress']}: {x.get('totalReports', 0)} reports/90d"
               + (f" (last {str(x['lastReportedAt'])[:10]})" if x.get("lastReportedAt") else "") for x in rows]
    return _result(tool, STATUS_OK, fields={
        "Resolved IPs": _fmt_list([x["ipAddress"] for x in rows]),
        "Reverse DNS / Hostnames": _fmt_list([h for x in rows for h in x.get("hostnames", [])] +
                                             [x.get("domain") for x in rows], 8),
        "Organization / ISP / Registrar": _fmt_list([x.get("isp") for x in rows]),
        "Reputation / Verdict": "; ".join(scores),
        "Abuse reports": "; ".join(reports),
        "Countries / Geo": _fmt_list([x.get("countryCode") for x in rows]),
        "Server / Technologies": ("Usage type: " + _fmt_list([x.get("usageType") for x in rows])),
    }, raw=raw)


def ipinfo(host: str, domain: str, ips: list[str], key: str) -> dict:
    tool = "IPinfo"
    if not ips:
        return _result(tool, STATUS_ERROR, "Domain did not resolve to an IPv4 address.")
    raw, rows, last_err = {}, [], None
    for ip in ips[:5]:
        r = requests.get(f"https://ipinfo.io/{ip}/json", params={"token": key}, timeout=TIMEOUT)
        if r.status_code != 200:
            last_err = _http_error(tool, r)
            if r.status_code in (401, 403, 429):
                break
            continue
        d = r.json()
        raw[ip] = d
        rows.append(d)
    if not rows:
        return last_err or _result(tool, STATUS_OK, "No data returned.", raw=raw)
    asns, orgs = set(), set()
    for x in rows:  # IPinfo returns org as "AS13335 Cloudflare, Inc."
        org = x.get("org", "")
        if org.startswith("AS") and " " in org:
            asn, name = org.split(" ", 1)
            asns.add(asn)
            orgs.add(name)
        elif org:
            orgs.add(org)
    geo = [", ".join(p for p in (x.get("city"), x.get("region"), x.get("country")) if p) for x in rows]
    return _result(tool, STATUS_OK, fields={
        "Resolved IPs": _fmt_list([x.get("ip") for x in rows]),
        "Reverse DNS / Hostnames": _fmt_list([x.get("hostname") for x in rows]),
        "Organization / ISP / Registrar": _fmt_list(orgs),
        "ASN": _fmt_list(asns),
        "Countries / Geo": _fmt_list(geo),
    }, raw=raw)


def greynoise(host: str, domain: str, ips: list[str], key: str) -> dict:
    """GreyNoise Community API: is the IP internet background noise / a known benign service?"""
    tool = "GreyNoise"
    if not ips:
        return _result(tool, STATUS_ERROR, "Domain did not resolve to an IPv4 address.")
    raw, verdicts, names, last_err = {}, [], set(), None
    for ip in ips[:5]:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                         headers={"key": key, "Accept": "application/json"}, timeout=TIMEOUT)
        if r.status_code == 404:  # IP never observed by GreyNoise sensors
            raw[ip] = r.json() if r.content else {}
            verdicts.append(f"{ip}: not observed (no internet-scan noise seen)")
            continue
        if r.status_code != 200:
            last_err = _http_error(tool, r)
            if r.status_code in (401, 403, 429):
                break
            continue
        d = r.json()
        raw[ip] = d
        flags = []
        if d.get("noise"):
            flags.append("internet noise")
        if d.get("riot"):
            flags.append("known benign service (RIOT)")
        verdicts.append(f"{ip}: {d.get('classification', 'unknown')}" + (f" ({', '.join(flags)})" if flags else "")
                        + (f", last seen {d['last_seen']}" if d.get("last_seen") else ""))
        if d.get("name") and d["name"] != "unknown":
            names.add(d["name"])
    if not raw:
        return last_err or _result(tool, STATUS_OK, "No data returned.", raw=raw)
    return _result(tool, STATUS_OK, fields={
        "Resolved IPs": _fmt_list(list(raw)),
        "Organization / ISP / Registrar": _fmt_list(names),
        "Reputation / Verdict": "; ".join(verdicts),
    }, raw=raw)


# name -> (function, env-var for the key, signup URL)
PROVIDERS: dict[str, tuple[Callable, str, str]] = {
    "VirusTotal":     (virustotal,     "VT_API_KEY",              "https://www.virustotal.com/gui/my-apikey"),
    "Shodan":         (shodan,         "SHODAN_API_KEY",          "https://account.shodan.io"),
    "AbuseIPDB":      (abuseipdb,      "ABUSEIPDB_API_KEY",       "https://www.abuseipdb.com/account/api"),
    "IPinfo":         (ipinfo,         "IPINFO_API_KEY",          "https://ipinfo.io/account/token"),
    "GreyNoise":      (greynoise,      "GREYNOISE_API_KEY",       "https://viz.greynoise.io/account/api-key"),
}


# --------------------------------------------------------------------------- orchestration
def run_provider(name: str, host: str, domain: str, ips: list[str], key: str) -> dict:
    func = PROVIDERS[name][0]
    if not key:
        return _result(name, STATUS_NOKEY, "No API key supplied - skipped.")
    try:
        return func(host, domain, ips, key.strip())
    except requests.exceptions.Timeout:
        return _result(name, STATUS_ERROR, "Request timed out.")
    except requests.exceptions.RequestException as exc:
        return _result(name, STATUS_ERROR, f"Network error: {exc}")
    except Exception as exc:  # never let one tool crash the whole run
        return _result(name, STATUS_ERROR, f"Unexpected error: {type(exc).__name__}: {exc}")


def analyse(target: str, keys: dict[str, str], progress: Callable[[str], None] = lambda m: None) -> dict:
    """Run all providers in parallel and return a report dict."""
    host = normalise_target(target)
    domain = registrable_domain(host)
    progress(f"Target: {host} (apex domain: {domain})")
    ips = resolve_ips(host)
    progress(f"DNS resolution: {', '.join(ips) if ips else 'no IPv4 records found'}")

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(PROVIDERS)) as pool:
        futures = {n: pool.submit(run_provider, n, host, domain, ips, keys.get(n, "")) for n in PROVIDERS}
        for name, fut in futures.items():
            res = fut.result()
            results[name] = res
            progress(f"{name}: {res['status']}" + (f" - {res['message']}" if res["message"] else ""))
    return {
        "target": host, "domain": domain, "local_dns_ips": ips,
        "collected_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "results": results,
    }


def comparison_rows(report: dict) -> tuple[list[str], list[list[str]]]:
    """Return (header, rows) for the side-by-side table: one row per field, one column per tool."""
    tools = list(report["results"].keys())
    header = ["Attribute"] + tools
    rows = [[f] + [report["results"][t]["fields"].get(f, NA) for t in tools] for f in FIELDS]
    rows.insert(0, ["Query status"] + [
        report["results"][t]["status"] + (f" - {report['results'][t]['message']}" if report["results"][t]["message"] else "")
        for t in tools])
    return header, rows
