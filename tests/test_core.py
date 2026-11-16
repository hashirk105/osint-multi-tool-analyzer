"""Offline tests: HTTP is mocked, so no API keys or network are needed. Run: python -m unittest -v"""
import os, sys, tempfile, unittest
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import osint_core as core
from exporter import export_xlsx
from openpyxl import load_workbook


def resp(code, js):
    m = MagicMock(); m.status_code = code; m.json.return_value = js; return m


def fake_get(url, **kw):
    if "virustotal" in url and url.endswith("/subdomains"):
        return resp(200, {"data": [{"id": "www.example.com"}, {"id": "mail.example.com"}], "meta": {"count": 2}})
    if "virustotal" in url:
        return resp(200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20},
            "reputation": 5, "registrar": "TestRegistrar", "creation_date": 1262304000,
            "last_dns_records": [{"type": "A", "value": "93.184.216.34"}], "categories": {"x": "business"}}}})
    if "shodan" in url:
        return resp(200, {"ports": [80, 443], "vulns": [], "org": "EdgeCast", "country_name": "US",
                          "data": [{"product": "nginx", "version": "1.18"}]})
    if "abuseipdb" in url:
        return resp(200, {"data": {"ipAddress": "93.184.216.34", "abuseConfidenceScore": 0, "totalReports": 0,
                          "countryCode": "US", "isp": "EdgeCast", "usageType": "Content Delivery Network", "hostnames": []}})
    if "greynoise" in url:
        return resp(200, {"ip": "93.184.216.34", "noise": False, "riot": True, "classification": "benign", "name": "Edgecast"})
    if "ipinfo" in url:
        return resp(401, {"error": "bad token"})
    raise AssertionError(url)


class T(unittest.TestCase):
    def test_normalise(self):
        self.assertEqual(core.normalise_target("https://WWW.Example.com/a?b=1"), "www.example.com")
        self.assertEqual(core.registrable_domain("a.b.example.co.uk"), "example.co.uk")
        with self.assertRaises(ValueError): core.normalise_target("")

    @patch("osint_core.resolve_ips", return_value=["93.184.216.34"])
    @patch("osint_core.requests.get", side_effect=fake_get)
    def test_pipeline_and_export(self, *_):
        keys = {n: "k" for n in core.PROVIDERS}; pass
        rep = core.analyse("https://example.com", keys)
        self.assertEqual(rep["results"]["VirusTotal"]["status"], "OK")
        self.assertEqual(rep["results"]["IPinfo"]["status"], "ERROR")
        self.assertIn("80, 443", rep["results"]["Shodan"]["fields"]["Open ports"])
        path = os.path.join(tempfile.mkdtemp(), "o.xlsx"); export_xlsx(rep, path)
        wb = load_workbook(path)
        self.assertEqual(wb.sheetnames, ["Comparison", "Findings", "Coverage", "Raw JSON", "Metadata"])
        self.assertEqual(wb["Comparison"].max_column, 6)

    def test_missing_key(self):
        self.assertEqual(core.run_provider("Shodan", "a.com", "a.com", [], "")["status"], "NO API KEY")


if __name__ == "__main__":
    unittest.main()
