import unittest
from unittest.mock import patch
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
        
        # Alphanumeric pre-releases without dot separators (mixed tokens)
        self.assertEqual(kevlar.compare_versions("1.0.0-rc10", "1.0.0-rc2"), 1)
        self.assertEqual(kevlar.compare_versions("1.0.0-rc2", "1.0.0-rc10"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-rc10", "1.0.0-rc10"), 0)
        self.assertEqual(kevlar.compare_versions("1.0.0-rc", "1.0.0-rc10"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-rc10", "1.0.0-rc"), 1)
        self.assertEqual(kevlar.compare_versions("1.0.0-10rc", "1.0.0-2rc"), 1)
        self.assertEqual(kevlar.compare_versions("1.0.0-rc01", "1.0.0-rc1"), -1) # lexicographical fallback for ties with leading zeroes
        
        # Numeric vs non-numeric identifier precedence rule
        self.assertEqual(kevlar.compare_versions("1.0.0-alpha.10", "1.0.0-alpha.10rc"), -1)
        self.assertEqual(kevlar.compare_versions("1.0.0-alpha.11", "1.0.0-alpha.10rc"), -1)
        
    def test_classify_update(self):
        self.assertEqual(kevlar.classify_update("1.2.3", "1.2.3"), "up-to-date")
        self.assertEqual(kevlar.classify_update("1.2.3", "2.0.0"), "major")
        self.assertEqual(kevlar.classify_update("1!1.0.0", "2!1.0.0"), "major")
        self.assertEqual(kevlar.classify_update("1.2.3", "1.3.0"), "minor")
        self.assertEqual(kevlar.classify_update("1.2.3", "1.2.4"), "patch")
        self.assertEqual(kevlar.classify_update("1.2.3", "1.2.3.4"), "patch")
        
    def test_determine_update_type(self):
        # Only major update exists
        self.assertEqual(kevlar.determine_update_type("1.2.3", "1.2.3", "2.0.0"), "major")
        # Same major has minor update, and absolute has major
        self.assertEqual(kevlar.determine_update_type("1.2.3", "1.3.5", "2.0.0"), "minor-major")
        # Same major has patch update, and absolute has major
        self.assertEqual(kevlar.determine_update_type("1.2.3", "1.2.9", "2.0.0"), "patch-major")
        # Up to date
        self.assertEqual(kevlar.determine_update_type("1.2.3", "1.2.3", "1.2.3"), "up-to-date")

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

        # Malformed vector tests (no colons, multiple colons, safe ignore checks)
        self.assertEqual(kevlar.calculate_cvss2_score("AVN/AC:L/Au:N/C:P/I:P/A:P"), 7.5)  # AVN has no colon, ignored, AV falls back to 1.0 (N)
        self.assertEqual(kevlar.calculate_cvss2_score("AV:N:extra/AC:L/Au:N/C:P/I:P/A:P"), 7.5) # AV:N:extra has multiple colons, ignored, AV falls back to 1.0 (N)
        self.assertEqual(kevlar.calculate_cvss2_score("malformed_vector_with_no_colons"), 0.0) # all ignored, impact=0, score=0.0
        self.assertIsNone(kevlar.calculate_cvss2_score(None)) # Exception caught, returns None

        self.assertEqual(kevlar.calculate_cvss3_score("CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8) # AVN ignored, AV falls back to 0.85 (N)
        self.assertEqual(kevlar.calculate_cvss3_score("CVSS:3.1/AV:N:extra/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8) # AV:N:extra ignored, AV falls back to 0.85 (N)
        self.assertEqual(kevlar.calculate_cvss3_score("malformed_vector_with_no_colons"), 0.0) # all ignored, impact=0, score=0.0
        self.assertIsNone(kevlar.calculate_cvss3_score(None)) # Exception caught, returns None
        
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
        base_dir = os.path.realpath("C:/workspace/myproject")
        
        # Safe paths under base_dir
        self.assertTrue(kevlar._is_safe_path(base_dir, "C:/workspace/myproject"))
        self.assertTrue(kevlar._is_safe_path(base_dir, "C:/workspace/myproject/pom.xml"))
        self.assertTrue(kevlar._is_safe_path(base_dir, "C:/workspace/myproject/src/main/resources"))
        
        # Unsafe paths / Traversal outside base_dir
        self.assertFalse(kevlar._is_safe_path(base_dir, "C:/workspace/myproject/../otherproject/pom.xml"))
        self.assertFalse(kevlar._is_safe_path(base_dir, "C:/workspace/otherproject"))
        
        # Partial match avoidance (e.g. /workspace/myproject-other should not be safe under /workspace/myproject)
        self.assertFalse(kevlar._is_safe_path(base_dir, "C:/workspace/myproject-other"))

        # Test symlink traversal dynamically if supported by the OS and permission settings
        import tempfile
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                real_temp_dir = os.path.realpath(temp_dir)
                outside_file = os.path.join(os.path.dirname(real_temp_dir), "outside_secret.xml")
                # Create the outside file
                with open(outside_file, "w") as f:
                    f.write("secret content")
                try:
                    symlink_path = os.path.join(real_temp_dir, "symlink_pom.xml")
                    os.symlink(outside_file, symlink_path)
                    # The symlink is located inside the base directory, but points outside.
                    # It must be recognized as unsafe.
                    self.assertFalse(kevlar._is_safe_path(real_temp_dir, symlink_path))
                finally:
                    if os.path.exists(outside_file):
                        try:
                            os.remove(outside_file)
                        except OSError:
                            pass
        except (OSError, NotImplementedError):
            # Skip if the OS/environment prevents creating symlinks (e.g., Windows without Developer Mode)
            pass

    def test_maven_poms_cycles(self):
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            real_temp_dir = os.path.realpath(temp_dir)
            
            # Create a cycle: parent_pom -> child_pom -> parent_pom
            parent_pom_path = os.path.join(real_temp_dir, "pom.xml")
            child_dir = os.path.join(real_temp_dir, "child")
            os.makedirs(child_dir, exist_ok=True)
            child_pom_path = os.path.join(child_dir, "pom.xml")
            
            parent_xml = """<project>
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.test</groupId>
                <artifactId>parent</artifactId>
                <version>1.0.0</version>
                <packaging>pom</packaging>
                <modules>
                    <module>child</module>
                </modules>
            </project>"""
            
            child_xml = """<project>
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.test</groupId>
                <artifactId>child</artifactId>
                <version>1.0.0</version>
                <packaging>pom</packaging>
                <modules>
                    <module>..</module>
                </modules>
            </project>"""
            
            with open(parent_pom_path, "w", encoding="utf-8") as f:
                f.write(parent_xml)
            with open(child_pom_path, "w", encoding="utf-8") as f:
                f.write(child_xml)
                
            # Execute search. With cycles, it must not throw RecursionError.
            # It should return a list containing unique, absolute paths of both poms.
            try:
                poms = kevlar.find_all_maven_poms(parent_pom_path, base_dir=real_temp_dir)
            except RecursionError:
                self.fail("find_all_maven_poms raised RecursionError on cyclic dependencies")
                
            # Verify paths
            expected_poms = {
                os.path.abspath(parent_pom_path),
                os.path.abspath(child_pom_path)
            }
            self.assertEqual(set(poms), expected_poms)
            self.assertEqual(len(poms), 2)

    def test_security_xml_pre_validation(self):
        import xml.etree.ElementTree as ET
        
        # Safe XMLs
        safe_xml_1 = "<project><dependencies></dependencies></project>"
        safe_xml_2 = "<?xml version='1.0'?><root>Hello World</root>"
        # Should not raise exception
        kevlar.safe_et_fromstring(safe_xml_1)
        kevlar.safe_et_fromstring(safe_xml_2)
        
        # Dangerous XMLs with DOCTYPE / ENTITY
        unsafe_xml_1 = """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <root>&xxe;</root>"""
        unsafe_xml_2 = """<!ENTITY xxe SYSTEM "http://malicious.com">"""
        unsafe_xml_3 = """<!doctype foo>"""
        # Spaced out / Case-insensitive variants
        unsafe_xml_4 = """<!   doCType foo>"""
        unsafe_xml_5 = """<!   EnTiTy foo SYSTEM "bar">"""
        
        with self.assertRaises((ValueError, ET.ParseError)):
            kevlar.safe_et_fromstring(unsafe_xml_1)
        with self.assertRaises((ValueError, ET.ParseError)):
            kevlar.safe_et_fromstring(unsafe_xml_2)
        with self.assertRaises((ValueError, ET.ParseError)):
            kevlar.safe_et_fromstring(unsafe_xml_3)
        with self.assertRaises((ValueError, ET.ParseError)):
            kevlar.safe_et_fromstring(unsafe_xml_4)
        with self.assertRaises((ValueError, ET.ParseError)):
            kevlar.safe_et_fromstring(unsafe_xml_5)

        # Multi-encoding evasion tests (UTF-16 and UTF-32)
        payload = """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>"""
        
        encodings_with_bom = [
            ('utf-16-le', b'\xff\xfe'),
            ('utf-16-be', b'\xfe\xff'),
            ('utf-32-le', b'\xff\xfe\x00\x00'),
            ('utf-32-be', b'\x00\x00\xfe\xff'),
        ]
        
        encodings_no_bom = [
            'utf-16-le',
            'utf-16-be',
            'utf-32-le',
            'utf-32-be',
        ]
        
        # Test with BOM
        for enc, bom in encodings_with_bom:
            encoded_bytes = bom + payload.encode(enc)
            with self.assertRaises((ValueError, ET.ParseError)):
                kevlar.safe_et_fromstring(encoded_bytes)
                
            # Leading whitespace + BOM
            encoded_bytes_ws = bom + ("   \n  " + payload).encode(enc)
            with self.assertRaises((ValueError, ET.ParseError)):
                kevlar.safe_et_fromstring(encoded_bytes_ws)
                
        # Test without BOM
        for enc in encodings_no_bom:
            encoded_bytes = payload.encode(enc)
            with self.assertRaises((ValueError, ET.ParseError)):
                kevlar.safe_et_fromstring(encoded_bytes)
                
            # Leading whitespace (without BOM)
            encoded_bytes_ws = (" \n\t " + payload).encode(enc)
            with self.assertRaises((ValueError, ET.ParseError)):
                kevlar.safe_et_fromstring(encoded_bytes_ws)

    def test_security_xml_parser_protections(self):
        # 1. Depth <= 15 should succeed
        nested_ok = "<root>" + "<nested>" * 14 + "text" + "</nested>" * 14 + "</root>"
        root = kevlar.safe_et_fromstring(nested_ok)
        self.assertIsNotNone(root)
        
        # 2. Depth > 15 should fail
        nested_deep = "<root>" + "<nested>" * 15 + "text" + "</nested>" * 15 + "</root>"
        with self.assertRaises(ValueError) as ctx:
            kevlar.safe_et_fromstring(nested_deep)
        self.assertIn("Node depth exceeds limit", str(ctx.exception))
        
        # 3. DOCTYPE/ENTITY declarations should fail in parser
        xml_entity = "<!DOCTYPE root [<!ENTITY x \"y\">]><root>&x;</root>"
        with self.assertRaises(ValueError):
            kevlar.safe_et_fromstring(xml_entity)

        # 4. Total size limit check
        with self.assertRaises(ValueError) as ctx:
            kevlar.parse_secure_xml("<root>Some long text</root>", max_expanded_size=10)
        self.assertIn("Expanded data size limit exceeded", str(ctx.exception))

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

    def test_wizard_utilities(self):
        import kevlar_wizard
        from datetime import date, timedelta
        
        # 1. Test validate_date_str
        self.assertTrue(kevlar_wizard.validate_date_str("2026-12-31"))
        self.assertFalse(kevlar_wizard.validate_date_str("2026-13-01")) # Invalid month
        self.assertFalse(kevlar_wizard.validate_date_str("26-12-31"))   # Invalid year format
        self.assertFalse(kevlar_wizard.validate_date_str("invalid"))
        
        # 2. Test validate_date_future
        future_str = (date.today() + timedelta(days=5)).strftime("%Y-%m-%d")
        past_str = (date.today() - timedelta(days=5)).strftime("%Y-%m-%d")
        self.assertTrue(kevlar_wizard.validate_date_future(future_str))
        self.assertFalse(kevlar_wizard.validate_date_future(past_str))
        
        # 3. Test validate_version_str
        self.assertTrue(kevlar_wizard.validate_version_str("1.0.0"))
        self.assertTrue(kevlar_wizard.validate_version_str("1.2"))
        self.assertFalse(kevlar_wizard.validate_version_str("v1.0"))
        self.assertFalse(kevlar_wizard.validate_version_str("abc"))
        
        # 4. Test parse_selection
        self.assertEqual(kevlar_wizard.parse_selection("1, 2, 3", 5), [1, 2, 3])
        self.assertEqual(kevlar_wizard.parse_selection("1-3", 5), [1, 2, 3])
        self.assertEqual(kevlar_wizard.parse_selection("all", 5), [1, 2, 3, 4, 5])
        self.assertEqual(kevlar_wizard.parse_selection("1, 2-4, 5", 5), [1, 2, 3, 4, 5])
        self.assertIsNone(kevlar_wizard.parse_selection("1, 6", 5)) # Out of bounds
        self.assertIsNone(kevlar_wizard.parse_selection("abc", 5))  # Invalid syntax

    def test_check_semver_satisfies(self):
        # Basic validation
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", ">=1.2.3"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", "*"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", "any"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", ""))
        
        # Space-separated AND ranges (existing functionality)
        self.assertTrue(kevlar.check_semver_satisfies("1.5.0", ">=1.2.3 <2.0.0"))
        self.assertFalse(kevlar.check_semver_satisfies("2.1.0", ">=1.2.3 <2.0.0"))
        
        # Comma-separated AND ranges (with and without spaces)
        self.assertTrue(kevlar.check_semver_satisfies("1.5.0", ">=1.2.3,<=2.0.0"))
        self.assertTrue(kevlar.check_semver_satisfies("1.5.0", ">=1.2.3, <=2.0.0"))
        self.assertFalse(kevlar.check_semver_satisfies("2.1.0", ">=1.2.3,<=2.0.0"))
        self.assertFalse(kevlar.check_semver_satisfies("2.1.0", ">=1.2.3, <=2.0.0"))
        
        # Multiple OR ranges mixed with comma-separated ANDs
        self.assertTrue(kevlar.check_semver_satisfies("2.5.0", ">=1.2.3,<=2.0.0 || >=2.4.0,<=3.0.0"))
        self.assertFalse(kevlar.check_semver_satisfies("2.1.0", ">=1.2.3,<=2.0.0 || >=2.4.0,<=3.0.0"))
        self.assertTrue(kevlar.check_semver_satisfies("3.0.0", ">=1.2.3,<=2.0.0 || >=2.4.0,<=3.0.0"))

    def test_configuration_drift_validation(self):
        results = [
            # 1. Matching constraint
            {
                "name": "matching-pkg",
                "declared": "^1.2.0",
                "installed": "1.2.5",
                "status": "up-to-date",
                "error": None
            },
            # 2. Violating constraint
            {
                "name": "violating-pkg",
                "declared": "^1.2.0",
                "installed": "2.0.1",
                "status": "up-to-date",
                "error": None
            },
            # 3. Git URL declared - should be skipped
            {
                "name": "git-pkg",
                "declared": "git+https://github.com/foo/bar.git#semver:^1.2.0",
                "installed": "2.0.1",
                "status": "up-to-date",
                "error": None
            },
            # 4. Missing declared - should be skipped
            {
                "name": "missing-dec",
                "declared": "N/A",
                "installed": "1.0.0",
                "status": "up-to-date",
                "error": None
            },
            # 5. Missing installed - should be skipped
            {
                "name": "missing-inst",
                "declared": "^1.0.0",
                "installed": "N/A",
                "status": "up-to-date",
                "error": None
            }
        ]
        
        kevlar.validate_configuration_drift(results)
        
        # Verify matching-pkg: no change
        self.assertEqual(results[0]["status"], "up-to-date")
        self.assertIsNone(results[0]["error"])
        
        # Verify violating-pkg: changed to error, with drift error message
        self.assertEqual(results[1]["status"], "error")
        self.assertIsNotNone(results[1]["error"])
        self.assertIn("Configuration Drift", results[1]["error"])
        self.assertIn("violates declared constraint", results[1]["error"])
        
        # Verify git-pkg: no change
        self.assertEqual(results[2]["status"], "up-to-date")
        
        # Verify missing-dec: no change
        self.assertEqual(results[3]["status"], "up-to-date")
        
        # Verify missing-inst: no change
        self.assertEqual(results[4]["status"], "up-to-date")

    def test_npm_transitive_same_name_no_drift(self):
        results = [
            {
                "name": "tslib",
                "declared": "^2.3.0",
                "installed": "2.8.1",
                "status": "up-to-date",
                "error": None
            },
            {
                "name": "tslib",
                "declared": "^2.3.0",
                "installed": "1.14.1",
                "status": "up-to-date",
                "error": None
            }
        ]
        
        pkg_data = {
            "all_direct": {
                "tslib": "^2.3.0"
            }
        }
        direct_versions_lock = {
            "tslib": "2.8.1"
        }
        
        by_name = {}
        for idx, r in enumerate(results):
            if not r.get("is_engine", False):
                by_name.setdefault(r["name"], []).append(idx)
                
        for name, indices in by_name.items():
            if name in pkg_data["all_direct"] and len(indices) > 1:
                declared_constraint = pkg_data["all_direct"][name]
                installed_versions = [results[idx]["installed"] for idx in indices]
                direct_ver = kevlar.find_direct_installed_version(
                    name, declared_constraint, installed_versions, 
                    direct_versions_from_lock=direct_versions_lock
                )
                for idx in indices:
                    if results[idx]["installed"] != direct_ver:
                        results[idx]["declared"] = None
                        
        kevlar.validate_configuration_drift(results)
        
        self.assertEqual(results[0]["declared"], "^2.3.0")
        self.assertIsNone(results[0]["error"])
        self.assertIsNone(results[1]["declared"])
        self.assertIsNone(results[1]["error"])

    def test_export_html_report_prompt_parameters(self):
        import tempfile
        
        results = [
            # 1. Pip package (Composite target, same-major matches current)
            {
                "name": "certifi",
                "declared": "2022.12.7",
                "installed": "2022.12.7",
                "latest": "2022.12.7 (latest: 2026.6.17)",
                "status": "major",
                "deprecated": False,
                "error": None,
                "latest_same_major": "2022.12.7",
                "latest_absolute": "2026.6.17",
                "technology": "pip",
                "vulnerabilities": []
            },
            # 2. Npm package (Composite target, same-major is different from current)
            {
                "name": "lodash",
                "declared": "4.17.15",
                "installed": "4.17.15",
                "latest": "4.17.21 (latest: 5.0.0)",
                "status": "major",
                "deprecated": False,
                "error": None,
                "latest_same_major": "4.17.21",
                "latest_absolute": "5.0.0",
                "technology": "npm",
                "vulnerabilities": []
            },
            # 3. NuGet package (Simple target, outdated minor)
            {
                "name": "Newtonsoft.Json",
                "declared": "13.0.1",
                "installed": "13.0.1",
                "latest": "13.0.3",
                "status": "minor",
                "deprecated": False,
                "error": None,
                "latest_same_major": "13.0.3",
                "latest_absolute": "13.0.3",
                "technology": "nuget",
                "vulnerabilities": []
            },
            # 4. PHP package (Simple target, vulnerable but up-to-date)
            {
                "name": "guzzlehttp/guzzle",
                "declared": "7.5.0",
                "installed": "7.5.0",
                "latest": "7.5.0",
                "status": "up-to-date",
                "deprecated": False,
                "error": None,
                "latest_same_major": "7.5.0",
                "latest_absolute": "7.5.0",
                "technology": "php",
                "vulnerabilities": [
                    {"id": "GHSA-1111-2222-3333", "summary": "test vuln PHP", "severity": "HIGH", "details": ""}
                ]
            }
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            filepath = os.path.join(temp_dir, "report.html")
            kevlar.export_html_report(results, {}, filepath, vuls_enabled=True)
            
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                
            # Assert function definition and helper function in JS script block
            self.assertIn("function copiarPromptRemediacion(pkgName, ecosystem, currentVer, latestSameMajor, latestAbsolute, alertType, details, projName, projDir, depType, requiredBy)", content)
            self.assertIn("function copiarPromptRemediacionByIndex(i)", content)
            
            # Assert correct JSON structures are embedded in the report
            self.assertIn('"name": "certifi"', content)
            self.assertIn('"latest_same_major": "2022.12.7"', content)
            self.assertIn('"latest_absolute": "2026.6.17"', content)
            
            self.assertIn('"name": "lodash"', content)
            self.assertIn('"latest_same_major": "4.17.21"', content)
            self.assertIn('"latest_absolute": "5.0.0"', content)
            
            self.assertIn('"name": "Newtonsoft.Json"', content)
            self.assertIn('"latest_same_major": "13.0.3"', content)
            self.assertIn('"latest_absolute": "13.0.3"', content)
            
            self.assertIn('"name": "guzzlehttp/guzzle"', content)
            self.assertIn('"GHSA-1111-2222-3333"', content)
            
    def test_parse_package_lock_all_dep_types(self):
        import tempfile
        import json
        lock_data = {
            "name": "test-project",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "dependencies": {"direct-dep": "^1.0.0"},
                    "devDependencies": {"dev-dep": "^2.0.0"}
                },
                "node_modules/direct-dep": {
                    "version": "1.0.1",
                    "dependencies": {"transitive-dep": "^1.1.0"},
                    "peerDependencies": {"peer-dep": "^3.0.0"}
                },
                "node_modules/transitive-dep": {
                    "version": "1.1.2",
                    "optionalDependencies": {"opt-dep": "^4.0.0"}
                },
                "node_modules/peer-dep": {
                    "version": "3.0.1"
                },
                "node_modules/opt-dep": {
                    "version": "4.0.5"
                },
                "node_modules/direct-dep/node_modules/opt-dep": {
                    "version": "5.0.0"
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            json.dump(lock_data, tmp)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity, direct_versions = kevlar.parse_package_lock(tmp_path)
            self.assertEqual(resolved.get("direct-dep"), ["1.0.1"])
            self.assertEqual(resolved.get("transitive-dep"), ["1.1.2"])
            self.assertEqual(resolved.get("peer-dep"), ["3.0.1"])
            self.assertEqual(sorted(resolved.get("opt-dep")), ["4.0.5", "5.0.0"])
            
            self.assertIn("root", parents.get("direct-dep", []))
            self.assertIn("root", parents.get("dev-dep", []))
            self.assertIn("direct-dep", parents.get("transitive-dep", []))
            self.assertIn("direct-dep", parents.get("peer-dep", []))
            self.assertIn("transitive-dep", parents.get("opt-dep", []))
            self.assertEqual(direct_versions.get("direct-dep"), "1.0.1")
            self.assertEqual(direct_versions.get("opt-dep"), "4.0.5")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_yarn_lock_all_dep_types(self):
        import tempfile
        content = (
            "direct-dep@^1.0.0:\n"
            "  version \"1.0.1\"\n"
            "  dependencies:\n"
            "    transitive-dep \"^1.1.0\"\n"
            "\n"
            "transitive-dep@^1.1.0:\n"
            "  version \"1.1.2\"\n"
            "  optionalDependencies:\n"
            "    opt-dep \"^4.0.0\"\n"
            "\n"
            "opt-dep@^4.0.0:\n"
            "  version \"4.0.5\"\n"
            "  peerDependencies:\n"
            "    peer-dep \"^3.0.0\"\n"
            "\n"
            "peer-dep@^3.0.0:\n"
            "  version \"3.0.1\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity = kevlar.parse_yarn_lock(tmp_path)
            self.assertEqual(resolved.get("direct-dep"), ["1.0.1"])
            self.assertEqual(resolved.get("transitive-dep"), ["1.1.2"])
            self.assertEqual(resolved.get("opt-dep"), ["4.0.5"])
            self.assertEqual(resolved.get("peer-dep"), ["3.0.1"])
            
            self.assertIn("direct-dep", parents.get("transitive-dep", []))
            self.assertIn("transitive-dep", parents.get("opt-dep", []))
            self.assertIn("opt-dep", parents.get("peer-dep", []))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_pnpm_lock_all_dep_types(self):
        import tempfile
        content = (
            "lockfileVersion: '6.0'\n"
            "packages:\n"
            "  /direct-dep@1.0.1:\n"
            "    resolution: {integrity: sha512-abc}\n"
            "    dependencies:\n"
            "      transitive-dep: 1.1.2\n"
            "  /transitive-dep@1.1.2:\n"
            "    resolution: {integrity: sha512-def}\n"
            "    optionalDependencies:\n"
            "      opt-dep: 4.0.5\n"
            "  /opt-dep@4.0.5:\n"
            "    resolution: {integrity: sha512-ghi}\n"
            "    peerDependencies:\n"
            "      peer-dep: 3.0.1\n"
            "  /peer-dep@3.0.1:\n"
            "    resolution: {integrity: sha512-jkl}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity = kevlar.parse_pnpm_lock(tmp_path)
            self.assertEqual(resolved.get("direct-dep"), ["1.0.1"])
            self.assertEqual(resolved.get("transitive-dep"), ["1.1.2"])
            self.assertEqual(resolved.get("opt-dep"), ["4.0.5"])
            self.assertEqual(resolved.get("peer-dep"), ["3.0.1"])
            
            self.assertIn("direct-dep", parents.get("transitive-dep", []))
            self.assertIn("transitive-dep", parents.get("opt-dep", []))
            self.assertIn("opt-dep", parents.get("peer-dep", []))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_python_lock_parsers(self):
        import tempfile
        import json
        # Poetry (Detailed check)
        poetry_content = (
            "# Some metadata comments at start\n"
            "[metadata]\n"
            "lock-version = \"2.0\"\n"
            "\n"
            "[[package]]\n"
            "name = \"flask\"\n"
            "version = \"2.0.1\"\n"
            "description = \"A simple framework\"\n"
            "category = \"main\"\n"
            "optional = false\n"
            "python-versions = \">=3.6\"\n"
            "\n"
            "[package.dependencies]\n"
            "click = \">=7.1.2\"\n"
            "itsdangerous = \">=2.0\"\n"
            "\n"
            "[[package]]\n"
            "name = \"click\"\n"
            "version = \"8.0.1\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock") as tmp:
            tmp.write(poetry_content)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_poetry_lock(tmp_path)
            self.assertEqual(resolved.get("flask"), ["2.0.1"])
            self.assertEqual(resolved.get("click"), ["8.0.1"])
            self.assertIn("flask", parents.get("click", []))
            self.assertIn("flask", parents.get("itsdangerous", []))
        finally:
            os.remove(tmp_path)

        # Poetry exception check (should not raise, but print warning and return empty dicts)
        resolved, parents = kevlar.parse_poetry_lock("nonexistent_file_path.lock")
        self.assertEqual(resolved, {})
        self.assertEqual(parents, {})

        # PDM (Detailed check)
        pdm_content = (
            "# Some PDM comments\n"
            "[metadata]\n"
            "groups = [\"default\"]\n"
            "\n"
            "[[package]]\n"
            "name = \"django\"\n"
            "version = \"3.2.5\"\n"
            "dependencies = [\n"
            "    \"asgiref>=3.3.2,<4\",\n"
            "    \"sqlparse>=0.2.2\",\n"
            "]\n"
            "\n"
            "[[package]]\n"
            "name = \"asgiref\"\n"
            "version = \"3.4.1\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock") as tmp:
            tmp.write(pdm_content)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_pdm_lock(tmp_path)
            self.assertEqual(resolved.get("django"), ["3.2.5"])
            self.assertEqual(resolved.get("asgiref"), ["3.4.1"])
            self.assertIn("django", parents.get("asgiref", []))
            self.assertIn("django", parents.get("sqlparse", []))
        finally:
            os.remove(tmp_path)

        # PDM exception check
        resolved, parents = kevlar.parse_pdm_lock("nonexistent_file_path.lock")
        self.assertEqual(resolved, {})
        self.assertEqual(parents, {})

        # Pipenv (Pipfile.lock)
        pipfile_data = {
            "default": {
                "requests": {"version": "==2.25.1"}
            },
            "develop": {
                "pytest": {"version": "==6.2.4"}
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
            json.dump(pipfile_data, tmp)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_pipfile_lock(tmp_path)
            self.assertEqual(resolved.get("requests"), ["2.25.1"])
            self.assertEqual(resolved.get("pytest"), ["6.2.4"])
        finally:
            os.remove(tmp_path)

    def test_match_line_for_dependency(self):
        # npm / php
        self.assertTrue(kevlar.match_line_for_dependency('  "lodash": "^4.17.21"', 'lodash', 'npm'))
        self.assertTrue(kevlar.match_line_for_dependency('  "lodash": "^4.17.21"', 'lodash', 'php'))
        self.assertFalse(kevlar.match_line_for_dependency('  "lodash": "^4.17.21"', 'not-lodash', 'npm'))
        
        # pip
        self.assertTrue(kevlar.match_line_for_dependency('requests==2.25.1', 'requests', 'pip'))
        self.assertTrue(kevlar.match_line_for_dependency('  flask >= 2.0', 'flask', 'pip'))
        self.assertTrue(kevlar.match_line_for_dependency('    "itsdangerous>=2.0",', 'itsdangerous', 'pip'))
        self.assertFalse(kevlar.match_line_for_dependency('flask-login==0.5.0', 'flask', 'pip'))
        
        # nuget
        self.assertTrue(kevlar.match_line_for_dependency('<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />', 'Newtonsoft.Json', 'nuget'))
        
        # maven
        self.assertTrue(kevlar.match_line_for_dependency('    <artifactId>log4j-core</artifactId>', 'org.apache.logging.log4j:log4j-core', 'maven'))
        
        # go
        self.assertTrue(kevlar.match_line_for_dependency('\tgithub.com/gin-gonic/gin v1.7.2', 'github.com/gin-gonic/gin', 'go'))
        
        # rust
        self.assertTrue(kevlar.match_line_for_dependency('serde = "1.0"', 'serde', 'rust'))
        
        # ruby
        self.assertTrue(kevlar.match_line_for_dependency("gem 'rails'", 'rails', 'ruby'))
        
        # gradle
        self.assertTrue(kevlar.match_line_for_dependency("implementation 'com.google.guava:guava:30.1-jre'", 'com.google.guava:guava', 'gradle'))
        
        # fallback / unknown tech
        self.assertFalse(kevlar.match_line_for_dependency('some random line', 'package', 'unknown-tech'))

    def test_parse_composer_lock(self):
        import tempfile
        import json
        composer_data = {
            "packages": [
                {"name": "guzzlehttp/guzzle", "version": "7.4.1"}
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "9.5.10"}
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
            json.dump(composer_data, tmp)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_composer_lock(tmp_path)
            self.assertEqual(resolved.get("guzzlehttp/guzzle"), ["7.4.1"])
            self.assertEqual(resolved.get("phpunit/phpunit"), ["9.5.10"])
        finally:
            os.remove(tmp_path)

    def test_parse_go_mod(self):
        import tempfile
        content = (
            "module github.com/test/mod\n"
            "go 1.18\n"
            "require (\n"
            "    github.com/gin-gonic/gin v1.7.7\n"
            "    golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd // indirect\n"
            ")\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".mod") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, indirects = kevlar.parse_go_mod(tmp_path)
            self.assertEqual(resolved.get("github.com/gin-gonic/gin"), "v1.7.7")
            self.assertEqual(indirects.get("golang.org/x/crypto"), "v0.0.0-20220315160706-3147a52a75dd")
        finally:
            os.remove(tmp_path)

    def test_parse_cargo_lock(self):
        import tempfile
        content = (
            "[[package]]\n"
            "name = \"serde\"\n"
            "version = \"1.0.130\"\n"
            "dependencies = [\n"
            " \"serde_derive\",\n"
            "]\n"
            "\n"
            "[[package]]\n"
            "name = \"serde_derive\"\n"
            "version = \"1.0.130\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_cargo_lock(tmp_path)
            self.assertEqual(resolved.get("serde"), ["1.0.130"])
            self.assertEqual(resolved.get("serde_derive"), ["1.0.130"])
            self.assertIn("serde", parents.get("serde_derive", []))
        finally:
            os.remove(tmp_path)

    def test_parse_gemfile_lock(self):
        import tempfile
        content = (
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    rails (6.1.4)\n"
            "      activesupport (= 6.1.4)\n"
            "    activesupport (6.1.4)\n"
            "\n"
            "PLATFORMS\n"
            "  ruby\n"
            "\n"
            "DEPENDENCIES\n"
            "  rails\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_gemfile_lock(tmp_path)
            self.assertEqual(resolved.get("rails"), "6.1.4")
            self.assertEqual(resolved.get("activesupport"), "6.1.4")
            self.assertIn("rails", parents.get("activesupport", []))
        finally:
            os.remove(tmp_path)

    def test_parse_gradle_lockfile(self):
        import tempfile
        content = (
            "# This is a Gradle lockfile\n"
            "org.slf4j:slf4j-api:1.7.30=compileClasspath\n"
            "empty=empty\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lockfile") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved = kevlar.parse_gradle_lockfile(tmp_path)
            self.assertEqual(resolved.get("org.slf4j:slf4j-api"), "1.7.30")
        finally:
            os.remove(tmp_path)

    def test_parse_libs_versions_toml(self):
        import tempfile
        content = (
            "[versions]\n"
            "groovy = \"3.0.5\"\n"
            "\n"
            "[libraries]\n"
            "groovy-core = { module = \"org.codehaus.groovy:groovy\", version.ref = \"groovy\" }\n"
            "groovy-json = \"org.codehaus.groovy:groovy-json:3.0.5\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved = kevlar.parse_libs_versions_toml(tmp_path)
            self.assertEqual(resolved.get("org.codehaus.groovy:groovy"), "3.0.5")
            self.assertEqual(resolved.get("org.codehaus.groovy:groovy-json"), "3.0.5")
        finally:
            os.remove(tmp_path)

    def test_apply_suppressions_project_path_lookup(self):
        import tempfile
        import shutil
        import json
        
        # Create a temporary directory structure representing a project
        temp_dir = tempfile.mkdtemp()
        try:
            supp_data = {
                "metadata": {
                    "version": "1.0.0",
                    "last_modified": "2026-07-08",
                    "approved_by": "TestTeam"
                },
                "suppressions": [
                    {
                        "id": "CVE-2023-1000",
                        "package": "test-pkg",
                        "ecosystem": "npm",
                        "reason": "FALSE_POSITIVE",
                        "justification": "This is a dummy justification for testing path lookup.",
                        "expires_at": "2030-12-31"
                    }
                ]
            }
            
            # Write suppressions file directly into the project directory
            supp_path = os.path.join(temp_dir, "kevlar-suppressions.json")
            with open(supp_path, "w", encoding="utf-8") as f:
                json.dump(supp_data, f)
                
            results = [
                {
                    "name": "test-pkg",
                    "status": "up-to-date",
                    "installed": "1.0.0",
                    "declared": "1.0.0",
                    "deprecated": False,
                    "technology": "npm",
                    "vulnerabilities": [
                        {"id": "CVE-2023-1000", "summary": "test vuln", "severity": "HIGH", "details": ""}
                    ]
                }
            ]
            
            # Call apply_vulnerability_suppressions passing project_path and suppress_path=None
            kevlar.apply_vulnerability_suppressions(results, None, project_path=temp_dir)
            
            # The vulnerability should be successfully suppressed
            self.assertEqual(len(results[0]["vulnerabilities"]), 0)
            self.assertEqual(len(results[0]["suppressed_vulnerabilities"]), 1)
            self.assertEqual(results[0]["suppressed_vulnerabilities"][0]["suppressed_reason"], "FALSE_POSITIVE")
        finally:
            shutil.rmtree(temp_dir)

    def test_engine_abstraction(self):
        import tempfile
        import json
        import shutil
        import io
        
        # Test 1: verify that print_results_table/export_markdown_report/generate_html_report respect is_engine flag
        results = [
            {
                "name": "my-custom-engine",
                "declared": ">=1.0.0",
                "installed": "N/A",
                "latest": "2.0.0",
                "latest_same_major": None,
                "latest_absolute": None,
                "status": "minor",
                "deprecated": False,
                "error": None,
                "is_engine": True
            }
        ]
        
        # We can intercept stdout to see if print_results_table displays "Engine" type
        captured_output = io.StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        try:
            kevlar.print_results_table(results, pkg_data={}, show_all=True)
        finally:
            sys.stdout = original_stdout
            
        output_str = captured_output.getvalue()
        self.assertIn("Engine", output_str)
        self.assertIn("my-custom-engine", output_str)
        
        # Test 2: verify populate_remediation_recommendations finds the engine block correctly
        temp_dir = tempfile.mkdtemp()
        try:
            package_json_content = {
                "name": "test-project",
                "engines": {
                    "my-custom-engine": ">=1.0.0"
                }
            }
            with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as f:
                json.dump(package_json_content, f, indent=2)
                
            results_for_remed = [
                {
                    "name": "my-custom-engine",
                    "declared": ">=1.0.0",
                    "installed": "N/A",
                    "latest": "2.0.0",
                    "latest_same_major": None,
                    "latest_absolute": None,
                    "status": "minor",
                    "deprecated": False,
                    "error": None,
                    "technology": "npm",
                    "project_path": temp_dir,
                    "is_engine": True
                }
            ]
            
            kevlar.populate_remediation_recommendations(results_for_remed, temp_dir)
            
            remed = results_for_remed[0].get("remediation")
            self.assertIsNotNone(remed)
            self.assertEqual(os.path.basename(remed["manifest_path"]), "package.json")
            has_custom_engine = any("my-custom-engine" in item["html"] for item in remed["current_code"])
            self.assertTrue(has_custom_engine)
        finally:
            shutil.rmtree(temp_dir)

    def test_repo_resolution_debug_mode(self):
        import io
        from unittest.mock import patch
        
        # Save original values
        original_debug = kevlar.DEBUG_MODE
        original_fetch = kevlar._fetch_registry_json_or_xml
        
        def mock_fetch(*args, **kwargs):
            raise ValueError("Mock connection error")
            
        kevlar._fetch_registry_json_or_xml = mock_fetch
        
        try:
            # Case 1: DEBUG_MODE is False
            kevlar.DEBUG_MODE = False
            
            captured_output = io.StringIO()
            with patch('sys.stdout', new=captured_output):
                res_npm = kevlar.resolve_npm_repo("some-pkg")
                res_nuget = kevlar.resolve_nuget_repo("some-pkg", "1.0.0")
                res_maven = kevlar.resolve_maven_repo("https://repo.maven.org/", "org/some", "pkg", "1.0.0")
                
            self.assertIsNone(res_npm)
            self.assertIsNone(res_nuget)
            self.assertIsNone(res_maven)
            self.assertEqual(captured_output.getvalue(), "")
            
            # Case 2: DEBUG_MODE is True
            kevlar.DEBUG_MODE = True
            
            captured_output = io.StringIO()
            with patch('sys.stdout', new=captured_output):
                res_npm = kevlar.resolve_npm_repo("some-pkg")
                
            self.assertIsNone(res_npm)
            output = captured_output.getvalue()
            self.assertIn("Failed to resolve NPM repository for 'some-pkg'", output)
            self.assertIn("Mock connection error", output)
            self.assertIn("traceback", output.lower())
            
            captured_output = io.StringIO()
            with patch('sys.stdout', new=captured_output):
                res_nuget = kevlar.resolve_nuget_repo("some-pkg", "1.0.0")
                
            self.assertIsNone(res_nuget)
            output = captured_output.getvalue()
            self.assertIn("Failed to resolve NuGet repository for 'some-pkg' (version 1.0.0)", output)
            self.assertIn("Mock connection error", output)
            self.assertIn("traceback", output.lower())
            
            captured_output = io.StringIO()
            with patch('sys.stdout', new=captured_output):
                res_maven = kevlar.resolve_maven_repo("https://repo.maven.org/", "org/some", "pkg", "1.0.0")
                
            self.assertIsNone(res_maven)
            output = captured_output.getvalue()
            self.assertIn("Failed to resolve Maven repository for 'org/some:pkg' (version 1.0.0) from https://repo.maven.org/", output)
            self.assertIn("Mock connection error", output)
            self.assertIn("traceback", output.lower())
            
        finally:
            kevlar.DEBUG_MODE = original_debug
            kevlar._fetch_registry_json_or_xml = original_fetch

    def test_node_constraint_refactored(self):
        from datetime import date
        from unittest.mock import patch
        
        # Test _is_major_version_eol directly
        schedule = {
            "18": {"end": "2025-04-30"},
            "22": {"end": "2027-04-30"}
        }
        today = date(2026, 7, 12)
        
        self.assertTrue(kevlar._is_major_version_eol("18", schedule, today))
        self.assertFalse(kevlar._is_major_version_eol("22", schedule, today))
        self.assertFalse(kevlar._is_major_version_eol("99", schedule, today))
        
        # Mock schedule and date for analyze_node_constraint
        mock_schedule = {
            "18": {"maintenance": "2023-10-18", "end": "2025-04-30"},
            "20": {"maintenance": "2024-10-22", "end": "2026-04-30"},
            "22": {"maintenance": "2025-10-21", "end": "2027-04-30"},
            "24": {"maintenance": "2026-10-20", "end": "2028-04-30"}
        }
        
        with patch('kevlar.fetch_node_schedule', return_value=mock_schedule), \
             patch('kevlar.date') as mock_date:
            mock_date.today.return_value = today
            
            # Case 1: Wildcard/any
            status, depr, err, rec = kevlar.analyze_node_constraint("*")
            self.assertEqual(status, "minor")
            self.assertIn("wildcard or missing", depr)
            self.assertEqual(rec, ">=24.0.0")
            
            # Case 2: Only EOL
            status, depr, err, rec = kevlar.analyze_node_constraint("^18.0.0")
            self.assertEqual(status, "error")
            self.assertIsNone(depr)
            self.assertIn("only satisfies EOL versions", err)
            
            # Case 3: EOL and Supported
            status, depr, err, rec = kevlar.analyze_node_constraint(">=18.0.0")
            self.assertEqual(status, "minor")
            self.assertIsNone(err)
            self.assertIn("allows EOL versions", depr)
            
            # Case 4: Only Supported
            status, depr, err, rec = kevlar.analyze_node_constraint(">=22.0.0")
            self.assertEqual(status, "up-to-date")
            self.assertIsNone(depr)
            self.assertIsNone(err)
            self.assertEqual(rec, "v24")
            
            # Case 5: Offline scenario (empty schedule)
            with patch('kevlar.fetch_node_schedule', return_value={}):
                status, depr, err, rec = kevlar.analyze_node_constraint(">=22.0.0")
                self.assertEqual(status, "error")
                self.assertIsNone(depr)
                self.assertIn("We cannot recommend a valid version at this time as there is no internet connection.", err)
                self.assertEqual(rec, "unknown")

    def test_export_sarif_report(self):
        import tempfile
        import json
        
        results = [
            # 1. Package with vulnerabilities
            {
                "name": "flask",
                "installed": "2.0.0",
                "declared": "2.0.0",
                "status": "up-to-date",
                "technology": "pip",
                "deprecated": False,
                "vulnerabilities": [
                    {"id": "CVE-2023-3000", "summary": "flask vuln", "severity": "HIGH", "details": "Vulnerability details here"},
                    {"id": "CVE-2023-3001", "summary": "flask vuln 2", "severity": "MEDIUM", "details": ""}
                ]
            },
            # 2. Package with configuration drift
            {
                "name": "lodash",
                "installed": "4.17.21",
                "declared": "^4.17.0",
                "status": "error",
                "technology": "npm",
                "deprecated": False,
                "error": "Configuration Drift: Installed version '4.17.21' violates declared constraint '^4.17.0'"
            },
            # 3. Package with outdated major version
            {
                "name": "requests",
                "installed": "2.0.0",
                "declared": "2.0.0",
                "latest": "3.0.0",
                "status": "major",
                "technology": "pip",
                "deprecated": False
            },
            # 4. Deprecated package
            {
                "name": "deprecated-pkg",
                "installed": "1.0.0",
                "declared": "1.0.0",
                "status": "up-to-date",
                "technology": "pip",
                "deprecated": "This package is no longer maintained."
            }
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            filepath = os.path.join(temp_dir, "report.sarif")
            kevlar.export_sarif_report(results, filepath)
            
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, "r", encoding="utf-8") as f:
                report = json.load(f)
                
            # Verify structure
            self.assertEqual(report.get("$schema"), "https://schemastore.org/json/schema/sarif-2.1.0-rtm.5.json")
            self.assertEqual(report.get("version"), "2.1.0")
            self.assertIn("runs", report)
            self.assertEqual(len(report["runs"]), 1)
            
            run = report["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "Kevlar CheckDeps")
            self.assertEqual(run["tool"]["driver"]["version"], kevlar.VERSION)
            
            # Map of results by ruleId to verify correctness
            results_by_rule = {}
            for res in run["results"]:
                results_by_rule.setdefault(res["ruleId"], []).append(res)
                
            # 1. Vulnerability 1 (CVE-2023-3000) -> error
            self.assertIn("CVE-2023-3000", results_by_rule)
            v1 = results_by_rule["CVE-2023-3000"][0]
            self.assertEqual(v1["level"], "error")
            self.assertIn("flask", v1["message"]["text"])
            self.assertIn("flask vuln", v1["message"]["text"])
            
            # Vulnerability 2 (CVE-2023-3001) -> warning
            self.assertIn("CVE-2023-3001", results_by_rule)
            v2 = results_by_rule["CVE-2023-3001"][0]
            self.assertEqual(v2["level"], "warning")
            
            # 2. Configuration drift (KEVLAR-CONFIG-DRIFT) -> error
            self.assertIn("KEVLAR-CONFIG-DRIFT", results_by_rule)
            cd = results_by_rule["KEVLAR-CONFIG-DRIFT"][0]
            self.assertEqual(cd["level"], "error")
            self.assertIn("Configuration Drift", cd["message"]["text"])
            
            # 3. Outdated major (KEVLAR-OUTDATED-DEPENDENCY) -> error
            self.assertIn("KEVLAR-OUTDATED-DEPENDENCY", results_by_rule)
            od = results_by_rule["KEVLAR-OUTDATED-DEPENDENCY"][0]
            self.assertEqual(od["level"], "error")
            self.assertIn("requests", od["message"]["text"])
            
            # 4. Deprecated package (KEVLAR-DEPRECATED-PACKAGE) -> warning
            self.assertIn("KEVLAR-DEPRECATED-PACKAGE", results_by_rule)
            dp = results_by_rule["KEVLAR-DEPRECATED-PACKAGE"][0]
            self.assertEqual(dp["level"], "warning")
            self.assertIn("deprecated-pkg", dp["message"]["text"])
            self.assertIn("no longer maintained", dp["message"]["text"])
            
            # Rules verification
            rules = run["tool"]["driver"]["rules"]
            rule_ids = {r["id"] for r in rules}
            self.assertIn("CVE-2023-3000", rule_ids)
            self.assertIn("CVE-2023-3001", rule_ids)
            self.assertIn("KEVLAR-CONFIG-DRIFT", rule_ids)
            self.assertIn("KEVLAR-OUTDATED-DEPENDENCY", rule_ids)
            self.assertIn("KEVLAR-DEPRECATED-PACKAGE", rule_ids)

    def test_generate_sarif_run_consolidation(self):
        # Verify generate_sarif_run works and creates valid runs that can be combined in runs array
        results_project_1 = [
            {
                "name": "flask",
                "installed": "2.0.0",
                "declared": "2.0.0",
                "status": "up-to-date",
                "technology": "pip",
                "deprecated": False,
                "vulnerabilities": [
                    {"id": "CVE-2023-3000", "summary": "flask vuln", "severity": "HIGH", "details": ""}
                ]
            }
        ]
        results_project_2 = [
            {
                "name": "express",
                "installed": "4.17.1",
                "declared": "4.17.1",
                "status": "major",
                "technology": "npm",
                "deprecated": False,
                "latest": "5.0.0"
            }
        ]
        
        run_1 = kevlar.generate_sarif_run(results_project_1)
        run_2 = kevlar.generate_sarif_run(results_project_2)
        
        consolidated_log = {
            "$schema": "https://schemastore.org/json/schema/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [run_1, run_2]
        }
        
        self.assertEqual(len(consolidated_log["runs"]), 2)
        self.assertEqual(consolidated_log["runs"][0]["tool"]["driver"]["name"], "Kevlar CheckDeps")
        self.assertEqual(consolidated_log["runs"][0]["results"][0]["ruleId"], "CVE-2023-3000")
        self.assertEqual(consolidated_log["runs"][1]["results"][0]["ruleId"], "KEVLAR-OUTDATED-DEPENDENCY")

    def test_safe_urlopen_security_validations(self):
        from unittest.mock import patch, MagicMock
        import urllib.request
        
        # Test allowed schemes (https, http) using mocked urlopen
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MagicMock()
            
            try:
                kevlar.safe_urlopen("https://example.com/api", max_retries=1)
            except Exception as e:
                self.fail(f"safe_urlopen raised exception on valid HTTPS URL: {e}")
                
            try:
                kevlar.safe_urlopen("http://example.com/api", max_retries=1)
            except Exception as e:
                self.fail(f"safe_urlopen raised exception on valid HTTP URL: {e}")
                
        # Test disallowed schemes
        with self.assertRaises(ValueError) as ctx:
            kevlar.safe_urlopen("file:///etc/passwd")
        self.assertEqual(str(ctx.exception), "Protocolo de comunicación no permitido")
        
        with self.assertRaises(ValueError) as ctx:
            kevlar.safe_urlopen("ftp://example.com")
        self.assertEqual(str(ctx.exception), "Protocolo de comunicación no permitido")

        with self.assertRaises(ValueError) as ctx:
            kevlar.safe_urlopen("gopher://example.com")
        self.assertEqual(str(ctx.exception), "Protocolo de comunicación no permitido")
        
        # Test protocol smuggling / control characters
        with self.assertRaises(ValueError):
            kevlar.safe_urlopen("https://example.com\r\n/smuggle")
            
        with self.assertRaises(ValueError):
            kevlar.safe_urlopen("https://example.com\t/smuggle")

        with self.assertRaises(ValueError):
            kevlar.safe_urlopen("https://example.com\x00/smuggle")
            
        # Test request object with disallowed scheme
        req = urllib.request.Request("file:///etc/passwd")
        with self.assertRaises(ValueError):
            kevlar.safe_urlopen(req)

    def test_check_osv_vulnerabilities_chunking(self):
        from unittest.mock import patch, MagicMock
        import json

        # Prepare 1500 targets
        targets = []
        for i in range(1500):
            targets.append({
                "name": f"package-{i}",
                "declared": "1.0.0",
                "installed": ["1.0.0"]
            })

        call_count = 0
        def mock_urlopen_side_effect(req, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            data = req.data
            req_json = json.loads(data.decode("utf-8"))
            num_queries = len(req_json["queries"])
            results = [{"vulns": []} for _ in range(num_queries)]
            resp_bytes = json.dumps({"results": results}).encode("utf-8")
            
            mock_resp = MagicMock()
            mock_resp.read.return_value = resp_bytes
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        with patch("kevlar.safe_urlopen", side_effect=mock_urlopen_side_effect):
            res = kevlar.check_osv_vulnerabilities(targets, "npm", max_workers=2)
            self.assertEqual(call_count, 2)
            self.assertEqual(res, {})

    def test_check_osv_vulnerabilities_no_fallback(self):
        from unittest.mock import patch, MagicMock
        import json

        targets = [{"name": "lodash", "declared": "4.17.20", "installed": ["4.17.20"]}]
        
        batch_response = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-cached-123",
                            "summary": "Prototype pollution in lodash",
                            "details": "Details here...",
                            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                            "database_specific": {"severity": "CRITICAL"}
                        }
                    ]
                }
            ]
        }
        
        url_calls = []

        def mock_urlopen(req, *args, **kwargs):
            url = req.full_url if hasattr(req, 'full_url') else req
            url_calls.append(url)
            
            mock_resp = MagicMock()
            if "querybatch" in url:
                mock_resp.read.return_value = json.dumps(batch_response).encode("utf-8")
            else:
                mock_resp.read.return_value = b"{}"
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        with patch("kevlar.safe_urlopen", side_effect=mock_urlopen):
            res = kevlar.check_osv_vulnerabilities(targets, "npm", max_workers=2)
            
            self.assertTrue(any("querybatch" in u for u in url_calls))
            self.assertFalse(any("vulns/" in u for u in url_calls))
            self.assertIn(("lodash", "4.17.20"), res)
            vulns = res[("lodash", "4.17.20")]
            self.assertEqual(len(vulns), 1)
            self.assertEqual(vulns[0]["id"], "GHSA-cached-123")
            self.assertEqual(vulns[0]["summary"], "Prototype pollution in lodash")
            self.assertEqual(vulns[0]["severity"], "CVSS:3.0/9.8")

    def test_check_osv_vulnerabilities_with_fallback(self):
        from unittest.mock import patch, MagicMock
        import json
        import sys

        targets = [{"name": "lodash", "declared": "4.17.20", "installed": ["4.17.20"]}]
        
        batch_response = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-orphan-456",
                            "summary": "Temporary summary",
                            "details": "Temporary details",
                            "severity": [{"type": "CVSS_V3", "score": "5.0"}]
                        }
                    ]
                }
            ]
        }
        
        url_calls = []

        def mock_urlopen(req, *args, **kwargs):
            url = req.full_url if hasattr(req, 'full_url') else req
            url_calls.append(url)
            
            mock_resp = MagicMock()
            if "querybatch" in url:
                mock_resp.read.return_value = json.dumps(batch_response).encode("utf-8")
            elif "vulns/GHSA-orphan-456" in url:
                fallback_response = {
                    "id": "GHSA-orphan-456",
                    "summary": "Fallback summary",
                    "details": "Fallback details",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}]
                }
                mock_resp.read.return_value = json.dumps(fallback_response).encode("utf-8")
            else:
                mock_resp.read.return_value = b"{}"
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        original_write = sys.stdout.write
        has_deleted = False
        def mock_stdout_write(text):
            nonlocal has_deleted
            if not has_deleted:
                frame = sys._getframe()
                while frame:
                    if frame.f_code.co_name == "check_osv_vulnerabilities":
                        locals_ = frame.f_locals
                        if "hydrated_details" in locals_ and "GHSA-orphan-456" in locals_["hydrated_details"]:
                            locals_["hydrated_details"].pop("GHSA-orphan-456", None)
                            has_deleted = True
                            break
                    frame = frame.f_back
            original_write(text)

        with patch("kevlar.safe_urlopen", side_effect=mock_urlopen), \
             patch("sys.stdout.write", side_effect=mock_stdout_write):
            res = kevlar.check_osv_vulnerabilities(targets, "npm", max_workers=2)
            
            self.assertTrue(any("querybatch" in u for u in url_calls))
            self.assertTrue(any("vulns/GHSA-orphan-456" in u for u in url_calls))
            self.assertIn(("lodash", "4.17.20"), res)
            vulns = res[("lodash", "4.17.20")]
            self.assertEqual(len(vulns), 1)
            self.assertEqual(vulns[0]["id"], "GHSA-orphan-456")
            self.assertEqual(vulns[0]["summary"], "Fallback summary")
            self.assertEqual(vulns[0]["severity"], "CVSS:3.0/7.5")

    def test_check_npm_package_local_dependency(self):
        target_file = {
            "name": "my-local-lib",
            "declared": "file:libreria/libreria-example",
            "installed": ["file:libreria/libreria-example"]
        }
        res = kevlar.check_npm_package(target_file)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["latest"], "Local")
        self.assertEqual(res[0]["status"], "local")
        self.assertIsNone(res[0]["error"])
        
        target_link = {
            "name": "my-linked-lib",
            "declared": "link:../linked-lib",
            "installed": []
        }
        res_link = kevlar.check_npm_package(target_link)
        self.assertEqual(len(res_link), 1)
        self.assertEqual(res_link[0]["latest"], "Local")
        self.assertEqual(res_link[0]["status"], "local")
        self.assertIsNone(res_link[0]["error"])

    @patch("urllib.request.urlopen")
    def test_check_npm_package_not_found_registry(self, mock_urlopen):
        from urllib.error import HTTPError
        import io
        mock_urlopen.side_effect = HTTPError("url", 404, "Not Found", {}, io.BytesIO(b""))
        
        target = {
            "name": "my-private-package",
            "declared": "^1.0.0",
            "installed": ["1.0.0"]
        }
        res = kevlar.check_npm_package(target)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["latest"], "Local")
        self.assertEqual(res[0]["status"], "local")
        self.assertIsNone(res[0]["error"])

if __name__ == "__main__":
    unittest.main()
