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
            with self.assertRaises(ValueError):
                kevlar._validate_xml_raw_content(encoded_bytes)
                
            # Leading whitespace + BOM
            encoded_bytes_ws = bom + ("   \n  " + payload).encode(enc)
            with self.assertRaises(ValueError):
                kevlar._validate_xml_raw_content(encoded_bytes_ws)
                
        # Test without BOM
        for enc in encodings_no_bom:
            encoded_bytes = payload.encode(enc)
            with self.assertRaises(ValueError):
                kevlar._validate_xml_raw_content(encoded_bytes)
                
            # Leading whitespace (without BOM)
            encoded_bytes_ws = (" \n\t " + payload).encode(enc)
            with self.assertRaises(ValueError):
                kevlar._validate_xml_raw_content(encoded_bytes_ws)

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
                
            # Assert function definition and copierPromptRemediacion parameter signature in JS script block
            self.assertIn("function copiarPromptRemediacion(pkgName, ecosystem, currentVer, latestSameMajor, latestAbsolute, alertType, details, projName, projDir, depType, requiredBy)", content)
            
            # Assert correct arguments passed in buttons for the composite pip case
            self.assertIn("copiarPromptRemediacion('certifi', 'Python / pip', '2022.12.7', '2022.12.7', '2026.6.17'", content)
            
            # Assert correct arguments passed in buttons for the composite npm case
            self.assertIn("copiarPromptRemediacion('lodash', 'Node.js / npm', '4.17.15', '4.17.21', '5.0.0'", content)
            
            # Assert correct arguments passed for simple nuget case
            self.assertIn("copiarPromptRemediacion('Newtonsoft.Json', '.NET / NuGet', '13.0.1', '13.0.3', '13.0.3'", content)
            
            # Assert correct arguments passed for php vuln case
            self.assertIn("copiarPromptRemediacion('guzzlehttp/guzzle', 'PHP / Composer', '7.5.0', '7.5.0', '7.5.0'", content)
            
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
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            json.dump(lock_data, tmp)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity = kevlar.parse_package_lock(tmp_path)
            self.assertEqual(resolved.get("direct-dep"), ["1.0.1"])
            self.assertEqual(resolved.get("transitive-dep"), ["1.1.2"])
            self.assertEqual(resolved.get("peer-dep"), ["3.0.1"])
            self.assertEqual(resolved.get("opt-dep"), ["4.0.5"])
            
            self.assertIn("root", parents.get("direct-dep", []))
            self.assertIn("root", parents.get("dev-dep", []))
            self.assertIn("direct-dep", parents.get("transitive-dep", []))
            self.assertIn("direct-dep", parents.get("peer-dep", []))
            self.assertIn("transitive-dep", parents.get("opt-dep", []))
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
        # Poetry
        poetry_content = (
            "[[package]]\n"
            "name = \"flask\"\n"
            "version = \"2.0.1\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock") as tmp:
            tmp.write(poetry_content)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_poetry_lock(tmp_path)
            self.assertEqual(resolved.get("flask"), ["2.0.1"])
        finally:
            os.remove(tmp_path)

        # PDM
        pdm_content = (
            "[[package]]\n"
            "name = \"django\"\n"
            "version = \"3.2.5\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock") as tmp:
            tmp.write(pdm_content)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_pdm_lock(tmp_path)
            self.assertEqual(resolved.get("django"), ["3.2.5"])
        finally:
            os.remove(tmp_path)

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

if __name__ == "__main__":
    unittest.main()
