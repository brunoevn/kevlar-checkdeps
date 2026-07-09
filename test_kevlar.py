import unittest
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import kevlar

class TestKevlar(unittest.TestCase):
    
    def test_parse_semver(self):
        # 3 segments
        self.assertEqual(kevlar.parse_semver("1.2.3"), (0, 1, 2, 3, 0, ""))
        # 4 segments
        self.assertEqual(kevlar.parse_semver("1.2.3.4"), (0, 1, 2, 3, 4, ""))
        # Epoch
        self.assertEqual(kevlar.parse_semver("1!2.3.4"), (1, 2, 3, 4, 0, ""))
        # Pre-releases
        self.assertEqual(kevlar.parse_semver("1.2.3-alpha.1"), (0, 1, 2, 3, 0, "alpha.1"))
        self.assertEqual(kevlar.parse_semver("1.2.3a1"), (0, 1, 2, 3, 0, "a1"))
        # Platform suffix (should NOT be classified as pre-release)
        self.assertEqual(kevlar.parse_semver("31.1-jre"), (0, 31, 1, 0, 0, ""))
        
    def test_compare_versions(self):
        # Epoch comparison
        self.assertEqual(kevlar.compare_versions("1!2.0.0", "3.0.0"), 1)
        self.assertEqual(kevlar.compare_versions("1!1.0.0", "1!2.0.0"), -1)
        
        # 4-segment comparison
        self.assertEqual(kevlar.compare_versions("1.2.3.4", "1.2.3.3"), 1)
        self.assertEqual(kevlar.compare_versions("1.2.3.4", "1.2.3.5"), -1)
        self.assertEqual(kevlar.compare_versions("1.2.3.4", "1.2.3"), 1)
        
        # Pre-release comparison
        self.assertEqual(kevlar.compare_versions("1.0.0-alpha", "1.0.0-alpha.1"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-alpha.1", "1.0.0-alpha.beta"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-alpha.beta", "1.0.0-beta"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-beta", "1.0.0-beta.2"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-beta.2", "1.0.0-beta.11"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-beta.11", "1.0.0-rc.1"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-rc.1", "1.0.0"), -1)
        
    def test_classify_update(self):
        self.assertEqual(kevlar.classify_update("1.2.3", "1.2.3"), "up-to-date")
        self.assertEqual(kevlar.classify_update("1.2.3", "2.0.0"), "major")
        self.assertEqual(kevlar.classify_update("1!1.0.0", "2!1.0.0"), "major")
        self.assertEqual(kevlar.classify_update("1.2.3", "1.3.0"), "minor")
        self.assertEqual(kevlar.classify_update("1.2.3", "1.2.4"), "patch")
        self.assertEqual(kevlar.classify_update("1.2.3", "1.2.3.4"), "patch")
        
    def test_cvss_calculations(self):
        # CVSS v2
        cvss2_vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        score2 = kevlar.calculate_cvss2_score(cvss2_vector)
        self.assertAlmostEqual(score2, 7.5, places=1)
        
        # CVSS v3
        cvss3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score3 = kevlar.calculate_cvss3_score(cvss3_vector)
        self.assertAlmostEqual(score3, 9.8, places=1)
        
        # CVSS v4 approximation
        cvss4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        score4 = kevlar.calculate_cvss4_score_approx(cvss4_vector)
        self.assertAlmostEqual(score4, 9.8, places=1)
        
    def test_get_severity_level(self):
        vuln_critical = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        self.assertEqual(kevlar.get_severity_level(vuln_critical), "critical")
        
        vuln_medium = {"severity": "CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:N"}
        self.assertEqual(kevlar.get_severity_level(vuln_medium), "medium")
        
        vuln_v4 = {"severity": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
        self.assertEqual(kevlar.get_severity_level(vuln_v4), "critical")
        
    def test_clean_repo_url(self):
        self.assertEqual(kevlar.clean_repo_url("git+https://github.com/foo/bar.git"), "https://github.com/foo/bar")
        self.assertEqual(kevlar.clean_repo_url("git@github.com:foo/bar.git"), "https://github.com/foo/bar")
        self.assertEqual(kevlar.clean_repo_url("ssh://git@github.com/foo/bar.git"), "https://github.com/foo/bar")
        self.assertIsNone(kevlar.clean_repo_url("javascript:alert(1)"))
        self.assertIsNone(kevlar.clean_repo_url("ftp://malicious.com"))
        
    def test_requirements_txt_parser(self):
        temp_file = "scratch_requirements_test.txt"
        content = (
            "requests[security]==2.25.1\n"
            "django>=2.0,<3.0 # via web-framework\n"
            "gunicorn==1!20.0.4\n"
            "-r other-requirements.txt\n"
        )
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(content)
            
        try:
            deps, parents = kevlar.parse_requirements_txt(temp_file)
            self.assertEqual(deps.get("requests"), "==2.25.1")
            self.assertEqual(deps.get("django"), ">=2.0")
            self.assertEqual(deps.get("gunicorn"), "==1!20.0.4")
            self.assertNotIn("-r", deps)
            self.assertEqual(parents.get("django"), ["web-framework"])
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_security_is_safe_path(self):
        # Convert path formatting dynamically depending on operating system (ensure proper separators)
        base_dir = os.path.abspath("C:/workspace/myproject")
        
        # Safe paths under base_dir
        self.assertTrue(kevlar._is_safe_path(base_dir, "C:/workspace/myproject"))
        self.assertTrue(kevlar._is_safe_path(base_dir, "C:/workspace/myproject/pom.xml"))
        self.assertTrue(kevlar._is_safe_path(base_dir, "C:/workspace/myproject/src/main/resources"))
        
        # Unsafe paths / Traversal outside base_dir
        self.assertFalse(kevlar._is_safe_path(base_dir, "C:/workspace/myproject/../otherproject/pom.xml"))
        self.assertFalse(kevlar._is_safe_path(base_dir, "C:/workspace/otherproject"))
        
        # Partial match avoidance (e.g. /workspace/myproject-other should not be safe under /workspace/myproject)
        self.assertFalse(kevlar._is_safe_path(base_dir, "C:/workspace/myproject-other"))

    def test_security_xml_pre_validation(self):
        # Safe XMLs
        safe_xml_1 = "<project><dependencies></dependencies></project>"
        safe_xml_2 = "<?xml version='1.0'?><root>Hello World</root>"
        # Should not raise exception
        kevlar._validate_xml_raw_content(safe_xml_1)
        kevlar._validate_xml_raw_content(safe_xml_2)
        
        # Dangerous XMLs with DOCTYPE / ENTITY
        unsafe_xml_1 = """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <root>&xxe;</root>"""
        unsafe_xml_2 = """<!ENTITY xxe SYSTEM "http://malicious.com">"""
        unsafe_xml_3 = """<!doctype foo>"""
        # Spaced out / Case-insensitive variants
        unsafe_xml_4 = """<!   doCType foo>"""
        unsafe_xml_5 = """<!   EnTiTy foo SYSTEM "bar">"""
        
        with self.assertRaises(ValueError):
            kevlar._validate_xml_raw_content(unsafe_xml_1)
        with self.assertRaises(ValueError):
            kevlar._validate_xml_raw_content(unsafe_xml_2)
        with self.assertRaises(ValueError):
            kevlar._validate_xml_raw_content(unsafe_xml_3)
        with self.assertRaises(ValueError):
            kevlar._validate_xml_raw_content(unsafe_xml_4)
        with self.assertRaises(ValueError):
            kevlar._validate_xml_raw_content(unsafe_xml_5)

    def test_security_sanitize_error_message(self):
        import urllib.error
        import json
        import xml.etree.ElementTree as ET
        
        # HTTP Error 404
        http_404 = urllib.error.HTTPError("http://example.com", 404, "Not Found", {}, None)
        self.assertEqual(kevlar._sanitize_error_message(http_404, "pkg"), "Registry returned not found (404)")
        
        # HTTP Error 504
        http_504 = urllib.error.HTTPError("http://example.com", 504, "Gateway Timeout", {}, None)
        self.assertEqual(kevlar._sanitize_error_message(http_504, "pkg"), "Registry communication timeout")
        
        # URL Error timeout
        url_err_timeout = urllib.error.URLError("timed out")
        self.assertEqual(kevlar._sanitize_error_message(url_err_timeout, "pkg"), "Registry communication timeout")
        
        # JSON format error
        json_err = json.JSONDecodeError("Expecting value", "{}", 0)
        self.assertEqual(kevlar._sanitize_error_message(json_err, "pkg"), "Malformed registry response format")
        
        # XML parse error
        xml_err = ET.ParseError("unclosed token")
        self.assertEqual(kevlar._sanitize_error_message(xml_err, "pkg"), "Malformed manifest format")
        
        # Custom ValueError
        val_err = ValueError("XML parsing rejected: entity detected")
        self.assertEqual(kevlar._sanitize_error_message(val_err, "pkg"), "Malformed manifest format")
        
        # Generic Exception
        generic_err = Exception("Internal database connection string leaked: postgres://user:pwd@host:5432/db")
        self.assertEqual(kevlar._sanitize_error_message(generic_err, "pkg"), "Unexpected execution error during analysis")

    def test_validate_suppressions_schema(self):
        # Valid schema
        valid_data = {
            "metadata": {
                "version": "1.0",
                "last_modified": "2026-07-08",
                "approved_by": "SecOps"
            },
            "suppressions": [
                {
                    "id": "CVE-2023-1234",
                    "package": "requests",
                    "ecosystem": "pip",
                    "reason": "NOT_AFFECTED_BY_VULNERABILITY",
                    "justification": "This is a detailed technical justification that meets length requirement.",
                    "expires_at": "2026-12-31"
                }
            ]
        }
        # Should not raise exception
        kevlar.validate_suppressions_schema(valid_data)

        # Invalid metadata version
        invalid_meta_version = dict(valid_data)
        invalid_meta_version["metadata"] = dict(valid_data["metadata"], version="abc")
        with self.assertRaises(ValueError):
            kevlar.validate_suppressions_schema(invalid_meta_version)

        # Invalid reason enum
        invalid_reason = {
            "metadata": valid_data["metadata"],
            "suppressions": [
                {
                    "id": "CVE-2023-1234",
                    "package": "requests",
                    "reason": "UNSUPPORTED_REASON_HERE",
                    "justification": "This is a detailed technical justification that meets length requirement.",
                    "expires_at": "2026-12-31"
                }
            ]
        }
        with self.assertRaises(ValueError):
            kevlar.validate_suppressions_schema(invalid_reason)

    def test_apply_suppressions_logic(self):
        import tempfile
        import json
        from datetime import date, timedelta
        
        # Build temp json suppressions file
        future_date = (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")
        past_date = (date.today() - timedelta(days=30)).strftime("%Y-%m-%d")
        
        supp_data = {
            "metadata": {
                "version": "1.0.0",
                "last_modified": "2026-07-08",
                "approved_by": "SecurityTeam"
            },
            "suppressions": [
                {
                    "id": "CVE-2023-3000",
                    "package": "flask",
                    "ecosystem": "pip",
                    "reason": "NOT_AFFECTED_BY_VULNERABILITY",
                    "justification": "Technical justification for flask vulnerability bypass.",
                    "expires_at": future_date,
                    "approved_by": "Bob the Reviewer"
                },
                {
                    "id": "*",
                    "package": "lodash",
                    "ecosystem": "npm",
                    "reason": "FALSE_POSITIVE",
                    "justification": "Technical justification for lodash wildcard bypass.",
                    "expires_at": future_date
                },
                {
                    "id": "CVE-2023-4000",
                    "package": "expired-pkg",
                    "ecosystem": "pip",
                    "reason": "ACCEPTED_TEMPORARY_RISK",
                    "justification": "This rule has expired and should not be matched.",
                    "expires_at": past_date
                }
            ]
        }
        
        # Write to temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            json.dump(supp_data, tmp)
            tmp_path = tmp.name
            
        try:
            results = [
                {
                    "name": "flask",
                    "status": "up-to-date",
                    "installed": "2.0.0",
                    "declared": "2.0.0",
                    "deprecated": False,
                    "technology": "pip",
                    "vulnerabilities": [
                        {"id": "CVE-2023-3000", "summary": "flask vuln", "severity": "HIGH", "details": ""}
                    ]
                },
                {
                    "name": "lodash",
                    "status": "up-to-date",
                    "installed": "4.17.21",
                    "declared": "4.17.21",
                    "deprecated": False,
                    "technology": "npm",
                    "vulnerabilities": [
                        {"id": "CVE-2023-5000", "summary": "lodash vuln 1", "severity": "MEDIUM", "details": ""},
                        {"id": "CVE-2023-6000", "summary": "lodash vuln 2", "severity": "LOW", "details": ""}
                    ]
                },
                {
                    "name": "expired-pkg",
                    "status": "up-to-date",
                    "installed": "1.0.0",
                    "declared": "1.0.0",
                    "deprecated": False,
                    "technology": "pip",
                    "vulnerabilities": [
                        {"id": "CVE-2023-4000", "summary": "expired vuln", "severity": "MEDIUM", "details": ""}
                    ]
                }
            ]
            
            # Apply suppressions
            kevlar.apply_vulnerability_suppressions(results, tmp_path)
            
            # flask checks: CVE-2023-3000 should be suppressed and enriched
            flask_res = results[0]
            self.assertEqual(len(flask_res["vulnerabilities"]), 0)
            self.assertEqual(len(flask_res["suppressed_vulnerabilities"]), 1)
            supp_vuln = flask_res["suppressed_vulnerabilities"][0]
            self.assertEqual(supp_vuln["suppressed_reason"], "NOT_AFFECTED_BY_VULNERABILITY")
            self.assertEqual(supp_vuln["justification"], "Technical justification for flask vulnerability bypass.")
            self.assertEqual(supp_vuln["expires_at"], future_date)
            self.assertEqual(supp_vuln["approved_by"], "Bob the Reviewer")
            
            # lodash checks: wildcard '*' matches all vulnerabilities
            lodash_res = results[1]
            self.assertEqual(len(lodash_res["vulnerabilities"]), 0)
            self.assertEqual(len(lodash_res["suppressed_vulnerabilities"]), 2)
            
            # expired-pkg checks: should NOT be suppressed since rule expired
            expired_res = results[2]
            self.assertEqual(len(expired_res["vulnerabilities"]), 1)
            self.assertEqual(len(expired_res["suppressed_vulnerabilities"]), 0)
            
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
