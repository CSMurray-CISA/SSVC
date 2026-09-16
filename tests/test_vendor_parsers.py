import unittest
from unittest.mock import patch

from bs4 import BeautifulSoup

from scripts import update_vendors as vendor


class VendorParserTests(unittest.TestCase):
    def test_generic_cvss_table(self):
        doc = BeautifulSoup("""
        <table><tr><th>Category</th><th>Impact</th><th>Severity</th><th>Score</th><th>Vector</th><th>CVE</th></tr>
        <tr><td>Out-of-bounds write</td><td>Code execution</td><td>Critical</td><td>9.8</td>
        <td>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</td><td>CVE-2026-12345</td></tr></table>
        """, "html.parser")
        rows = vendor.generic_table_records(doc, "Test Product")
        self.assertEqual(rows[0]["cve"], "CVE-2026-12345")
        self.assertEqual(rows[0]["cvss"], "9.8")
        self.assertEqual(rows[0]["severity"], "CRITICAL")

    @patch.object(vendor, "soup")
    def test_apple_component_blocks(self, mock_soup):
        mock_soup.return_value = BeautifulSoup("""
        <h1>About the security content of TestOS</h1><p>Released September 14, 2026</p>
        <h3>WebKit</h3><p>Impact: Processing web content may lead to code execution</p>
        <p>Description: A memory issue was fixed.</p><p>CVE-2026-12345: Researcher</p>
        """, "html.parser")
        doc = vendor.parse_apple("https://support.apple.com/test")
        self.assertEqual(doc["vulnerabilities"][0]["component"], "WebKit")
        self.assertIn("code execution", doc["vulnerabilities"][0]["description"])

    @patch.object(vendor, "soup")
    def test_mediatek_label_value_rows(self, mock_soup):
        mock_soup.return_value = BeautifulSoup("""
        <h1>September 2026 MediaTek Security Bulletin</h1><table>
        <tr><th>CVE</th><td>CVE-2026-12345</td></tr><tr><th>Subcomponent</th><td>Modem</td></tr>
        <tr><th>Severity</th><td>High</td></tr><tr><th>Description</th><td>Possible system crash.</td></tr>
        <tr><th>Affected Chipsets</th><td>MT1234</td></tr></table>
        """, "html.parser")
        doc = vendor.parse_mediatek("https://www.mediatek.com/test")
        item = doc["vulnerabilities"][0]
        self.assertEqual((item["component"], item["severity"], item["product"]), ("Modem", "HIGH", "MT1234"))

    def test_csaf_conversion(self):
        data = {"vulnerabilities": [{"cve": "CVE-2026-12345", "notes": [{"category": "description", "text": "Issue"}],
          "scores": [{"cvss_v3": {"baseScore": 8.8, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "version": "3.1"}}]}]}
        item = vendor.csaf_records(data, "Product")[0]
        self.assertEqual(item["cvss"], "8.8")
        self.assertEqual(item["severity"], "HIGH")

    @patch.object(vendor, "load_kev", side_effect=RuntimeError("temporary outage"))
    def test_kev_failure_is_non_blocking(self, _mock_load):
        warnings = []
        self.assertIsNone(vendor.safe_load_kev(warnings))
        self.assertIn("temporary outage", warnings[0])


if __name__ == "__main__":
    unittest.main()
