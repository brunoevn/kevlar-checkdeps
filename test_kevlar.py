import os
import sys
import unittest
from unittest.mock import patch

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import kevlar


class TestKevlar(unittest.TestCase):
    def setUp(self):
        kevlar.clear_kevlar_cache()

    def tearDown(self):
        kevlar.clear_kevlar_cache()

    def test_parse_sln_path_traversal(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            sln_path = os.path.join(tmpdir, "test.sln")

            normal_proj_dir = os.path.join(tmpdir, "NormalProj")
            os.makedirs(normal_proj_dir, exist_ok=True)
            normal_proj_path = os.path.join(normal_proj_dir, "NormalProj.csproj")
            with open(normal_proj_path, "w") as f:
                f.write("<Project></Project>")

            malicious_path_relative = "..\\MaliciousProj.csproj"
            malicious_path_absolute = os.path.abspath(os.path.join(tmpdir, "..", "MaliciousProj.csproj"))

            with open(sln_path, "w") as f:
                f.write('Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "NormalProj", "NormalProj\\NormalProj.csproj", "{GUID1}"\n')
                f.write(f'Project("{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}") = "MaliciousProj", "{malicious_path_relative}", "{{GUID2}}"\n')

            created_malicious = False
            try:
                with open(malicious_path_absolute, "w") as f:
                    f.write("<Project></Project>")
                created_malicious = True
            except PermissionError:
                pass

            if created_malicious:
                project_paths = kevlar.parse_sln_file(sln_path)
                self.assertEqual(len(project_paths), 1)
                self.assertTrue(project_paths[0].endswith("NormalProj.csproj"))
                self.assertFalse(any("MaliciousProj.csproj" in p for p in project_paths))
                try:
                    os.remove(malicious_path_absolute)
                except OSError:
                    pass

    def test_parse_slnx_xxe_protection(self):
        import os
        import tempfile
        xxe_payload = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE Solution [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Solution>
  <Project Path="src/&xxe;.csproj" />
</Solution>"""
        with tempfile.TemporaryDirectory() as tmpdir:
            slnx_path = os.path.join(tmpdir, "test.slnx")
            with open(slnx_path, "w", encoding="utf-8") as f:
                f.write(xxe_payload)

            # safe_et_parse must raise ValueError due to forbidden DOCTYPE declaration
            project_paths = kevlar.parse_sln_file(slnx_path)
            self.assertEqual(project_paths, [])

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

    def test_calculate_cvss2_score_exhaustive(self):
        vectors = {
            "AV:L/AC:H/Au:M/C:N/I:N/A:N": 0.0,
            "AV:N/AC:L/Au:N/C:C/I:C/A:C": 10.0,
            "AV:A/AC:M/Au:S/C:P/I:P/A:P": 4.9,
            "AV:L/AC:L/Au:N/C:C/I:N/A:N": 4.9,
            "AV:N/AC:M/Au:N/C:N/I:P/A:N": 4.3,
            "AV:N/AC:L/Au:N/C:N/I:N/A:C": 7.8
        }
        for vector, expected_score in vectors.items():
            self.assertEqual(kevlar.calculate_cvss2_score(vector), expected_score)

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

        # CVSS v3 edge cases and missing values
        cvss3_vector_scope_c = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        score3_scope_c = kevlar.calculate_cvss3_score(cvss3_vector_scope_c)
        self.assertAlmostEqual(score3_scope_c, 10.0, places=1)
        self.assertAlmostEqual(kevlar.calculate_cvss3_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"), 0.0, places=1)
        # CVSS v4 approximation edge cases mapping to v3 equivalents
        # AT:P -> AC:H
        cvss4_at_p = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        self.assertAlmostEqual(kevlar.calculate_cvss4_score_approx(cvss4_at_p), 8.1, places=1)

        # UI:A/R -> UI:R
        cvss4_ui_a = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        self.assertAlmostEqual(kevlar.calculate_cvss4_score_approx(cvss4_ui_a), 8.7, places=1)

        # SC/SI/SA -> S:C
        cvss4_sc_h = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N"
        self.assertAlmostEqual(kevlar.calculate_cvss4_score_approx(cvss4_sc_h), 10.0, places=1)

        cvss4_si_l = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:L/SA:N"
        self.assertAlmostEqual(kevlar.calculate_cvss4_score_approx(cvss4_si_l), 10.0, places=1)

        self.assertIsNone(kevlar.calculate_cvss4_score_approx(None))

        # Malformed vector tests (no colons, multiple colons, safe ignore checks)
        self.assertEqual(kevlar.calculate_cvss2_score("AVN/AC:L/Au:N/C:P/I:P/A:P"), 7.5)  # AVN has no colon, ignored, AV falls back to 1.0 (N)
        self.assertEqual(kevlar.calculate_cvss2_score("AV:N:extra/AC:L/Au:N/C:P/I:P/A:P"), 7.5) # AV:N:extra has multiple colons, ignored, AV falls back to 1.0 (N)
        self.assertEqual(kevlar.calculate_cvss2_score("malformed_vector_with_no_colons"), 0.0) # all ignored, impact=0, score=0.0
        self.assertIsNone(kevlar.calculate_cvss2_score(None)) # Exception caught, returns None

        # CVSS v3 malformed vector tests
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

        vuln_malicious = {"id": "MAL-2025-1234", "severity": "UNKNOWN"}
        self.assertEqual(kevlar.get_severity_level(vuln_malicious), "malicious")
        
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
            self.assertEqual(deps.get("django"), ">=2.0,<3.0")
            self.assertEqual(deps.get("gunicorn"), "==1!20.0.4")
            self.assertNotIn("-r", deps)
            self.assertEqual(parents.get("django"), ["web-framework"])
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_requirements_txt_pep508_and_markers(self):
        temp_file = "scratch_pep508_test.txt"
        content = (
            "requests @ https://github.com/psf/requests/archive/refs/tags/v2.26.0.tar.gz\n"
            "urllib3[brotli]>=1.26.0; python_version >= '3.0'\n"
            "legacy-lib==0.1.0; python_version < '2.0'\n"
            "platform-specific==1.0.0; sys_platform == 'nonexistent-os'\n"
            "matching-platform==1.0.0; sys_platform == '" + sys.platform + "'\n"
        )
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(content)
            
        try:
            deps, _parents = kevlar.parse_requirements_txt(temp_file)
            # URL dependency
            self.assertEqual(deps.get("requests"), "@ https://github.com/psf/requests/archive/refs/tags/v2.26.0.tar.gz")
            # Marker matching current environment should be present
            self.assertEqual(deps.get("urllib3"), ">=1.26.0")
            self.assertEqual(deps.get("matching-platform"), "==1.0.0")
            # Marker not matching current environment should be absent
            self.assertNotIn("legacy-lib", deps)
            self.assertNotIn("platform-specific", deps)
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

        # Case normalization testing (especially relevant on Windows)
        if os.name == "nt":
            self.assertTrue(kevlar._is_safe_path("C:/Workspace/MyProject", "c:/workspace/myproject/pom.xml"))
            self.assertTrue(kevlar._is_safe_path("c:/workspace/myproject", "C:/WORKSPACE/MYPROJECT/src/main.py"))
            self.assertFalse(kevlar._is_safe_path("C:/Workspace/MyProject", "c:/workspace/otherproject/pom.xml"))

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

    def test_parse_secure_xml_encodings(self):
        # UTF-8
        content_utf8 = b'<?xml version="1.0" encoding="UTF-8"?><root>test</root>'
        root = kevlar.parse_secure_xml(content_utf8)
        self.assertEqual(root.tag, "root")
        self.assertEqual(root.text, "test")

        # Latin-1
        content_latin1 = b'<?xml version="1.0" encoding="iso-8859-1"?><root>\xe9</root>'
        root = kevlar.parse_secure_xml(content_latin1)
        self.assertEqual(root.tag, "root")
        self.assertEqual(root.text, "\xe9")

        # Invalid encoding fallbacks
        content_invalid = b'<?xml version="1.0" encoding="invalid-enc"?><root>test</root>'
        root = kevlar.parse_secure_xml(content_invalid)
        self.assertEqual(root.tag, "root")
        self.assertEqual(root.text, "test")

        # No encoding specified, fallback to utf-8
        content_no_enc = b'<root>test</root>'
        root = kevlar.parse_secure_xml(content_no_enc)
        self.assertEqual(root.tag, "root")
        self.assertEqual(root.text, "test")

    def test_parse_secure_xml_billion_laughs(self):
        # Billion laughs should be caught by forbid_doctype
        xml = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol1;</lolz>"""
        with self.assertRaises(ValueError) as ctx:
            kevlar.parse_secure_xml(xml)
        self.assertIn("XML contains forbidden DOCTYPE declarations", str(ctx.exception))

    def test_parse_secure_xml_external_entity(self):
        # XXE should be caught by forbid_doctype
        xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"""
        with self.assertRaises(ValueError) as ctx:
            kevlar.parse_secure_xml(xml)
        self.assertIn("XML contains forbidden DOCTYPE declarations", str(ctx.exception))

    def test_parse_secure_xml_depth_limit(self):
        xml = "<root>" + "<child>" * 20 + "</child>" * 20 + "</root>"
        with self.assertRaises(ValueError) as ctx:
            kevlar.parse_secure_xml(xml, max_depth=15)
        self.assertIn("Node depth exceeds limit", str(ctx.exception))

    def test_secure_xml_namespaces(self):
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <pom:project xmlns:pom="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <pom:modelVersion>4.0.0</pom:modelVersion>
            <pom:groupId>com.example</pom:groupId>
            <pom:artifactId>my-app</pom:artifactId>
            <pom:dependencies>
                <pom:dependency pom:scope="compile">
                    <pom:groupId>junit</pom:groupId>
                    <pom:artifactId>junit</pom:artifactId>
                </pom:dependency>
            </pom:dependencies>
        </pom:project>
        """
        root = kevlar.parse_secure_xml(xml_content)
        self.assertIsNotNone(root)
        self.assertEqual(root.tag, "{http://maven.apache.org/POM/4.0.0}project")
        
        # Test finding elements
        model_version = root.find("{http://maven.apache.org/POM/4.0.0}modelVersion")
        self.assertIsNotNone(model_version)
        self.assertEqual(model_version.text, "4.0.0")
        
        # Test attributes
        dependencies = root.find("{http://maven.apache.org/POM/4.0.0}dependencies")
        self.assertIsNotNone(dependencies)
        dep = dependencies.find("{http://maven.apache.org/POM/4.0.0}dependency")
        self.assertIsNotNone(dep)
        self.assertEqual(dep.attrib.get("{http://maven.apache.org/POM/4.0.0}scope"), "compile")

    def test_security_sanitize_error_message(self):
        import json
        import urllib.error
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
        import json
        import tempfile
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
        from datetime import date, timedelta

        import kevlar_wizard
        
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

        # Caret operator tests
        self.assertTrue(kevlar.check_semver_satisfies("0.5.0", "^0"))
        self.assertTrue(kevlar.check_semver_satisfies("0.5.0", "^0.x"))
        self.assertTrue(kevlar.check_semver_satisfies("0.5.0", "^0.*"))
        self.assertTrue(kevlar.check_semver_satisfies("0.2.7", "^0.2"))
        self.assertFalse(kevlar.check_semver_satisfies("0.5.0", "^0.2"))
        self.assertFalse(kevlar.check_semver_satisfies("0.0.3", "^0.0.x"))
        self.assertFalse(kevlar.check_semver_satisfies("0.0.5", "^0.0.x"))
        self.assertTrue(kevlar.check_semver_satisfies("0.0.3", "^0.0.3"))
        self.assertFalse(kevlar.check_semver_satisfies("0.0.5", "^0.0.3"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.7", "^1.2.3"))
        self.assertFalse(kevlar.check_semver_satisfies("2.0.0", "^1.2.3"))

        # Tilde operator tests
        self.assertTrue(kevlar.check_semver_satisfies("1.2.7", "~1.2"))
        self.assertFalse(kevlar.check_semver_satisfies("1.3.0", "~1.2"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.7", "~1.2.3"))
        self.assertFalse(kevlar.check_semver_satisfies("1.3.0", "~1.2.3"))
        self.assertTrue(kevlar.check_semver_satisfies("1.8.0", "~1"))
        self.assertFalse(kevlar.check_semver_satisfies("2.0.0", "~1"))

    def test_check_semver_satisfies_caching(self):
        """Validates that check_semver_satisfies leverages LRU caching and that clear_kevlar_cache flushes it."""
        kevlar.clear_kevlar_cache()
        initial_info = kevlar.check_semver_satisfies.cache_info()
        self.assertEqual(initial_info.currsize, 0)
        self.assertEqual(initial_info.hits, 0)

        # First call -> cache miss
        res1 = kevlar.check_semver_satisfies("1.2.3", ">=1.0.0 <2.0.0")
        self.assertTrue(res1)
        info1 = kevlar.check_semver_satisfies.cache_info()
        self.assertEqual(info1.currsize, 1)
        self.assertEqual(info1.hits, 0)
        self.assertEqual(info1.misses, initial_info.misses + 1)

        # Second call with identical arguments -> cache hit
        res2 = kevlar.check_semver_satisfies("1.2.3", ">=1.0.0 <2.0.0")
        self.assertTrue(res2)
        info2 = kevlar.check_semver_satisfies.cache_info()
        self.assertEqual(info2.currsize, 1)
        self.assertEqual(info2.hits, 1)

        # Third call with new arguments -> cache miss, currsize = 2
        res3 = kevlar.check_semver_satisfies("2.5.0", "^2.0.0")
        self.assertTrue(res3)
        info3 = kevlar.check_semver_satisfies.cache_info()
        self.assertEqual(info3.currsize, 2)
        self.assertEqual(info3.hits, 1)

        # Flush cache via clear_kevlar_cache
        kevlar.clear_kevlar_cache()
        cleared_info = kevlar.check_semver_satisfies.cache_info()
        self.assertEqual(cleared_info.currsize, 0)
        self.assertEqual(cleared_info.hits, 0)

    def test_check_semver_satisfies_extended_edge_cases(self):
        """Validates edge cases including operator whitespace, complex compound expressions, and boundaries."""
        # Operator whitespace normalization
        self.assertTrue(kevlar.check_semver_satisfies("1.5.0", " >= 1.2.0   <  2.0.0 "))
        self.assertTrue(kevlar.check_semver_satisfies("2.0.0", " = 2.0.0 "))
        self.assertTrue(kevlar.check_semver_satisfies("2.0.0", " == 2.0.0 "))
        self.assertFalse(kevlar.check_semver_satisfies("2.0.1", " == 2.0.0 "))

        # Wildcard variations
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", "1.x"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", "1.*"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", "1.2.x"))
        self.assertTrue(kevlar.check_semver_satisfies("1.2.3", "1.2.*"))
        self.assertFalse(kevlar.check_semver_satisfies("1.3.0", "1.2.x"))
        self.assertFalse(kevlar.check_semver_satisfies("2.0.0", "1.x"))

        # Multiple compound OR and comma combinations
        self.assertTrue(kevlar.check_semver_satisfies("0.9.5", "<1.0.0 || >=2.0.0"))
        self.assertTrue(kevlar.check_semver_satisfies("2.5.0", "<1.0.0 || >=2.0.0"))
        self.assertFalse(kevlar.check_semver_satisfies("1.5.0", "<1.0.0 || >=2.0.0"))

        # Zero-series semver edge cases
        self.assertTrue(kevlar.check_semver_satisfies("0.0.1", "^0.0.1"))
        self.assertFalse(kevlar.check_semver_satisfies("0.0.2", "^0.0.1"))
        self.assertTrue(kevlar.check_semver_satisfies("0.1.5", "^0.1.0"))
        self.assertFalse(kevlar.check_semver_satisfies("0.2.0", "^0.1.0"))

        # Falsy and universal ranges
        self.assertTrue(kevlar.check_semver_satisfies("1.0.0", None))
        self.assertTrue(kevlar.check_semver_satisfies("1.0.0", ""))
        self.assertTrue(kevlar.check_semver_satisfies("1.0.0", "*"))
        self.assertTrue(kevlar.check_semver_satisfies("1.0.0", "any"))
        self.assertTrue(kevlar.check_semver_satisfies("1.0.0", "x"))

    def test_check_semver_satisfies_ecosystems_matrix(self):
        """Validates semver constraint satisfaction patterns covering all supported technology ecosystems."""
        # 1. Node.js (npm / yarn / pnpm) patterns: Carets, tildes, wildcards, and disjunctive ranges
        self.assertTrue(kevlar.check_semver_satisfies("18.12.1", ">=16.0.0 <17.0.0 || >=18.0.0 <19.0.0"))
        self.assertFalse(kevlar.check_semver_satisfies("17.5.0", ">=16.0.0 <17.0.0 || >=18.0.0 <19.0.0"))
        self.assertTrue(kevlar.check_semver_satisfies("4.17.21", "^4.17.0"))
        self.assertTrue(kevlar.check_semver_satisfies("2.3.4", "~2.3.0"))

        # 2. Python (PEP 440 / requirements.txt / pyproject.toml) patterns: Comma-separated bounds and exact pins
        self.assertTrue(kevlar.check_semver_satisfies("3.10.4", ">=3.8, <=3.11"))
        self.assertFalse(kevlar.check_semver_satisfies("3.12.0", ">=3.8, <=3.11"))
        self.assertTrue(kevlar.check_semver_satisfies("2.28.1", "==2.28.1"))
        self.assertFalse(kevlar.check_semver_satisfies("2.28.2", "==2.28.1"))

        # 3. Rust (Cargo.toml) patterns: Caret default conventions and zero-major crates
        self.assertTrue(kevlar.check_semver_satisfies("1.0.197", "^1.0.0"))
        self.assertTrue(kevlar.check_semver_satisfies("0.4.19", "^0.4"))
        self.assertFalse(kevlar.check_semver_satisfies("0.5.0", "^0.4"))

        # 4. Ruby (Gemfile / Bundler) patterns: Pessimistic constraint equivalents
        self.assertTrue(kevlar.check_semver_satisfies("7.0.4", "~7.0.0"))
        self.assertFalse(kevlar.check_semver_satisfies("7.1.0", "~7.0.0"))

        # 5. PHP (Composer) patterns: Pipe-separated OR ranges, caret and tilde prefixes
        self.assertTrue(kevlar.check_semver_satisfies("8.1.5", "^8.0 || ^8.1"))
        self.assertTrue(kevlar.check_semver_satisfies("8.0.28", "^8.0 || ^8.1"))
        self.assertFalse(kevlar.check_semver_satisfies("9.0.0", "^8.0 || ^8.1"))
        self.assertTrue(kevlar.check_semver_satisfies("8.0.5", "~8.0.0 || ~8.1.0"))
        self.assertFalse(kevlar.check_semver_satisfies("8.2.0", "~8.0.0 || ~8.1.0"))

        # 6. Go (go.mod) patterns: Semver tags with and without v-prefix
        self.assertTrue(kevlar.check_semver_satisfies("v1.18.2", ">=1.18.0"))
        self.assertTrue(kevlar.check_semver_satisfies("1.18.2", ">=1.18.0"))

        # 7. .NET / C# (NuGet / CPM) & Java (Maven / Gradle) patterns: Minimum bounds and exact versions
        self.assertTrue(kevlar.check_semver_satisfies("13.0.3", ">=13.0.1"))
        self.assertTrue(kevlar.check_semver_satisfies("2.13.4", ">=2.0.0"))
        self.assertTrue(kevlar.check_semver_satisfies("3.0.0", "3.0.0"))

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
            },
            # 6. Workspace package - should be skipped
            {
                "name": "workspace-pkg",
                "declared": "workspace:^",
                "installed": "0.0.0-use.local",
                "status": "up-to-date",
                "error": None
            },
            # 7. Yarn Berry npm: aliased package - should be parsed and matched correctly
            {
                "name": "npm-alias-pkg",
                "declared": "npm:esbuild-wasm@^0.23.0",
                "installed": "0.23.0",
                "status": "up-to-date",
                "error": None
            },
            # 8. Catalog reference - should be skipped
            {
                "name": "catalog-pkg",
                "declared": "catalog:",
                "installed": "5.9.2",
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

        # Verify workspace-pkg: no change
        self.assertEqual(results[5]["status"], "up-to-date")

        # Verify npm-alias-pkg: no change
        self.assertEqual(results[6]["status"], "up-to-date")

        # Verify catalog-pkg: no change
        self.assertEqual(results[7]["status"], "up-to-date")

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
            self.assertIn("function copiarPromptRemediacion(pkgName, ecosystem, currentVer, latestSameMajor, latestAbsolute, alertType, details, projName, projDir, depType, requiredBy, manifestFile, manifestLine)", content)
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

    def test_export_html_report_multi_technology(self):
        import tempfile
        results = [
            {
                "name": "express",
                "declared": "^4.17.1",
                "installed": "4.17.1",
                "latest": "4.18.2",
                "status": "minor",
                "deprecated": False,
                "error": None,
                "technology": "npm",
                "project_path": "/app",
                "dep_type": "Direct"
            },
            {
                "name": "rails",
                "declared": "~> 7.0",
                "installed": "7.0.0",
                "latest": "7.1.0",
                "status": "minor",
                "deprecated": False,
                "error": None,
                "technology": "ruby",
                "project_path": "/app",
                "dep_type": "Direct"
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.html")
            kevlar.export_html_report(results, {}, filepath)
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                
            self.assertIn('id="dropdown-technology"', content)
            self.assertIn('const UNIQUE_TECHNOLOGIES = ["npm", "ruby"];', content)
            self.assertIn('badge-tech-npm', content)
            self.assertIn('badge-tech-ruby', content)

    def test_export_html_report_xss_escaping(self):
        import tempfile
        results = [
            {
                "name": "vulnerable-pkg",
                "declared": "1.0.0",
                "installed": "1.0.0",
                "latest": "1.0.0",
                "status": "up-to-date",
                "deprecated": False,
                "error": None,
                "technology": "<script>alert('xss-tech')</script>",
                "project_path": "</script><script>alert('xss-path')</script>",
                "dep_type": "Direct"
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.html")
            kevlar.export_html_report(results, {}, filepath)
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            # Verify dangerous script tags are escaped as unicode escape sequences in JS block
            self.assertNotIn("</script><script>alert('xss-path')</script>", content)
            self.assertIn("\\u003c/script\\u003e\\u003cscript\\u003ealert('xss-path')\\u003c/script\\u003e", content)
            self.assertIn("\\u003cscript\\u003ealert('xss-tech')\\u003c/script\\u003e", content)

            
    def test_parse_package_lock_all_dep_types(self):
        import json
        import tempfile
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
            resolved, parents, _integrity, direct_versions = kevlar.parse_package_lock(tmp_path)
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
            resolved, parents, _integrity = kevlar.parse_yarn_lock(tmp_path)
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

    def test_parse_yarn_lock_berry(self):
        import tempfile
        content = (
            "__metadata:\n"
            "  version: 8\n"
            "  cacheKey: 10\n"
            "\n"
            "\"ansi-regex@npm:^5.0.1\":\n"
            "  version: 5.0.1\n"
            "  resolution: \"ansi-regex@npm:5.0.1\"\n"
            "  checksum: 10/303a270be7b275215c0e43cf2bf114a7\n"
            "\n"
            "\"@babel/core@npm:^7.12.3\":\n"
            "  version: 7.12.3\n"
            "  resolution: \"@babel/core@npm:7.12.3\"\n"
            "  dependencies:\n"
            "    \"@babel/code-frame\": \"npm:^7.10.4\"\n"
            "  checksum: sha512:47b864a7ef14cf86c8d234771234a75a0b777a88523c14c56e3039d48b67f67747b864a7ef14cf86c8d234771234a75a0b777a88523c14c56e3039d48b67f677\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity = kevlar.parse_yarn_lock(tmp_path)
            self.assertEqual(resolved.get("ansi-regex"), ["5.0.1"])
            self.assertEqual(resolved.get("@babel/core"), ["7.12.3"])
            
            self.assertIn("@babel/core", parents.get("@babel/code-frame", []))
            
            # Check checksum conversions:
            # 10/303a270be7b275215c0e43cf2bf114a7 -> hex is 32 chars (md5/other?), stays as is since it is not standard length for sha1/sha256/sha512
            self.assertEqual(integrity.get(("ansi-regex", "5.0.1")), "303a270be7b275215c0e43cf2bf114a7")
            # For sha512:47b8... (128 hex chars), converted to base64 with sha512- prefix
            # 47b864a7ef14cf86c8d234771234a45a0b777a88523c14c56e3039d48b67f67747b864a7ef14cf86c8d234771234a75a0b777a88523c14c56e3039d48b67f677 hex -> base64 is R7hkp+8Uz4bI0jR3EjSkWgt3eohSPBTFbjCZ1ItnZ3xHuGSl7xTPhsjSNHcSxKR6C3eohSPBTFbjCZ1ItnZ3xw==
            self.assertEqual(integrity.get(("@babel/core", "7.12.3")), "sha512-R7hkp+8Uz4bI0jR3EjSnWgt3eohSPBTFbjA51Itn9ndHuGSn7xTPhsjSNHcSNKdaC3d6iFI8FMVuMDnUi2f2dw==")
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
            resolved, parents, _integrity = kevlar.parse_pnpm_lock(tmp_path)
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

    def test_parse_pnpm_lock_v9(self):
        import tempfile
        content = (
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            "  '@algolia/abtesting@1.1.0':\n"
            "    resolution: {integrity: sha512-abc}\n"
            "  '@angular/compiler-cli@20.3.26(@angular/compiler@20.3.26)(typescript@5.9.3)':\n"
            "    resolution: {integrity: sha512-def}\n"
            "  '@algolia/client-common@5.35.0':\n"
            "    resolution: {integrity: sha512-ghi}\n"
            "snapshots:\n"
            "  '@algolia/abtesting@1.1.0':\n"
            "    dependencies:\n"
            "      '@algolia/client-common': 5.35.0\n"
            "  '@angular/compiler-cli@20.3.26(@angular/compiler@20.3.26)(typescript@5.9.3)':\n"
            "    dependencies:\n"
            "      '@angular/compiler': 20.3.26\n"
            "  '@algolia/client-common@5.35.0': {}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, _integrity = kevlar.parse_pnpm_lock(tmp_path)
            self.assertEqual(resolved.get("@algolia/abtesting"), ["1.1.0"])
            self.assertEqual(resolved.get("@angular/compiler-cli"), ["20.3.26"])
            self.assertEqual(resolved.get("@algolia/client-common"), ["5.35.0"])
            
            self.assertIn("@algolia/abtesting", parents.get("@algolia/client-common", []))
            self.assertIn("@angular/compiler-cli", parents.get("@angular/compiler", []))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_pnpm_lock_peer_dep_slashes(self):
        import tempfile
        content = (
            "lockfileVersion: '9.0'\n"
            "snapshots:\n"
            "  'http-proxy-middleware@2.0.10(@types/express@4.17.25)(debug@4.4.3)':\n"
            "    dependencies:\n"
            "      '@types/express': 4.17.25\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, _integrity = kevlar.parse_pnpm_lock(tmp_path)
            self.assertEqual(resolved.get("http-proxy-middleware"), ["2.0.10"])
            self.assertNotIn("express", resolved)
            self.assertNotIn("4.17.25)", resolved.get("express", []))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


    def test_python_lock_parsers(self):
        import json
        import tempfile
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

    def test_parse_pyproject_toml(self):
        import tempfile
        toml_content = (
            "[project]\n"
            "name = \"my-project\"\n"
            "dependencies = [\n"
            "    \"requests>=2.28.0; python_version < '3.8'\",\n"
            "    \"flask[async] >= 2.0.0\",\n"
            "]\n"
            "[project.optional-dependencies]\n"
            "test = [\"pytest>=7.0.0\", \"mock\"]\n"
            "\n"
            "[tool.poetry.dependencies]\n"
            "python = \"^3.9\"\n"
            "urllib3 = \"^1.26.0\"\n"
            "toml = { version = \"^0.10.2\", extras = [\"test\"] }\n"
            "git-dep = { git = \"https://github.com/foo/bar.git\" }\n"
            "\n"
            "[tool.poetry.group.dev.dependencies]\n"
            "black = \"^22.3.0\"\n"
            "\n"
            "[tool.pdm.dev-dependencies]\n"
            "pdm-group = [\"mypy>=0.950\", \"tox\"]\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as tmp:
            tmp.write(toml_content)
            tmp_path = tmp.name
        try:
            deps = kevlar.parse_pyproject_toml(tmp_path)
            self.assertEqual(deps.get("requests"), ">=2.28.0")
            self.assertEqual(deps.get("flask"), ">=2.0.0")
            self.assertEqual(deps.get("pytest"), ">=7.0.0")
            self.assertEqual(deps.get("mock"), "*")
            self.assertNotIn("python", deps)
            self.assertEqual(deps.get("urllib3"), "^1.26.0")
            self.assertEqual(deps.get("toml"), "^0.10.2")
            self.assertEqual(deps.get("git-dep"), "*")
            self.assertEqual(deps.get("black"), "^22.3.0")
            self.assertEqual(deps.get("mypy"), ">=0.950")
            self.assertEqual(deps.get("tox"), "*")
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
        self.assertTrue(kevlar.match_line_for_dependency('    "mcp[cli]>=1.0",', 'mcp', 'pip'))
        self.assertFalse(kevlar.match_line_for_dependency('flask-login==0.5.0', 'flask', 'pip'))
        
        # nuget
        self.assertTrue(kevlar.match_line_for_dependency('<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />', 'Newtonsoft.Json', 'nuget'))
        
        # maven
        self.assertTrue(kevlar.match_line_for_dependency('    <artifactId>log4j-core</artifactId>', 'org.apache.logging.log4j:log4j-core', 'maven'))
        
        # go
        self.assertTrue(kevlar.match_line_for_dependency('\tgithub.com/gin-gonic/gin v1.7.2', 'github.com/gin-gonic/gin', 'go'))
        
        # rust
        self.assertTrue(kevlar.match_line_for_dependency('serde = "1.0"', 'serde', 'rust'))
        self.assertTrue(kevlar.match_line_for_dependency('[dependencies.clap]', 'clap', 'rust'))
        
        # ruby
        self.assertTrue(kevlar.match_line_for_dependency("gem 'rails'", 'rails', 'ruby'))
        
        # gradle
        self.assertTrue(kevlar.match_line_for_dependency("implementation 'com.google.guava:guava:30.1-jre'", 'com.google.guava:guava', 'gradle'))
        
        # fallback / unknown tech
        self.assertFalse(kevlar.match_line_for_dependency('some random line', 'package', 'unknown-tech'))

    def test_parse_cargo_toml(self):
        import tempfile
        content = (
            '[dependencies]\n'
            'bincode = "1.0"\n'
            '\n'
            '[dependencies.clap]\n'
            'version = "4.6.1"\n'
            'optional = true\n'
            'features = ["wrap_help"]\n'
            '\n'
            '[target.\'cfg(target_os = "macos")\'.dependencies]\n'
            'plist = "1.9.0"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            deps = kevlar.parse_cargo_toml(tmp_path)
            self.assertIn("bincode", deps)
            self.assertIn("clap", deps)
            self.assertIn("plist", deps)
            self.assertNotIn("version", deps)
            self.assertNotIn("optional", deps)
            self.assertNotIn("features", deps)
        finally:
            os.remove(tmp_path)

    def test_parse_composer_lock(self):
        import json
        import tempfile
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
            resolved, _parents = kevlar.parse_composer_lock(tmp_path)
            self.assertEqual(resolved.get("guzzlehttp/guzzle"), ["7.4.1"])
            self.assertEqual(resolved.get("phpunit/phpunit"), ["9.5.10"])
        finally:
            os.remove(tmp_path)

    def test_parse_go_mod(self):
        import tempfile
        content = (
            "module github.com/test/mod\n"
            "go 1.18\n"
            "\n"
            "require (\n"
            "    github.com/gin-gonic/gin v1.7.7\n"
            "    golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd // indirect\n"
            ")\n"
            "\n"
            "require github.com/google/uuid v1.4.0 // indirect\n"
            "require github.com/original/mod v1.0.0\n"
            "require github.com/local/mod v2.0.0\n"
            "require github.com/replaced/block v3.0.0\n"
            "\n"
            "replace github.com/original/mod => github.com/fork/mod v1.1.0\n"
            "replace github.com/local/mod => ./local/path\n"
            "replace (\n"
            "    github.com/replaced/block v3.0.0 => github.com/fork/block v3.1.0\n"
            ")\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".mod") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, indirects, *_ = kevlar.parse_go_mod(tmp_path)
            self.assertEqual(resolved.get("github.com/gin-gonic/gin"), "v1.7.7")
            self.assertEqual(indirects.get("golang.org/x/crypto"), "v0.0.0-20220315160706-3147a52a75dd")
            self.assertEqual(indirects.get("github.com/google/uuid"), "v1.4.0")
            self.assertEqual(resolved.get("github.com/fork/mod"), "v1.1.0")
            self.assertNotIn("github.com/original/mod", resolved)
            self.assertEqual(resolved.get("github.com/fork/block"), "v3.1.0")
            self.assertNotIn("github.com/replaced/block", resolved)
            self.assertEqual(resolved.get("github.com/local/mod"), "v2.0.0")
        finally:
            os.remove(tmp_path)

    def test_parse_go_mod_edge_cases(self):
        import tempfile
        content = (
            "module example.com/my-module\n"
            "go 1.21\n"
            "toolchain go1.21.3\n"
            "\n"
            "// Comment before require block\n"
            "require (\n"
            "    example.com/pseudo-pkg v0.0.0-20230101000000-abcdef123456 // indirect\n"
            "    example.com/specific-replaced-pkg v1.0.0\n"
            ")\n"
            "\n"
            "exclude example.com/excluded-pkg v2.0.0\n"
            "\n"
            "replace example.com/specific-replaced-pkg v1.0.0 => example.com/specific-replaced-pkg v1.0.1\n"
            "replace (\n"
            "    example.com/another-replaced-pkg => example.com/another-fork v2.0.0-rc1\n"
            ")\n"
            "require example.com/another-replaced-pkg v1.5.0\n"
            "require (\n"
            "    // Empty require block test\n"
            ")\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".mod") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, indirects, *_ = kevlar.parse_go_mod(tmp_path)
            self.assertEqual(indirects.get("example.com/pseudo-pkg"), "v0.0.0-20230101000000-abcdef123456")
            self.assertEqual(resolved.get("example.com/specific-replaced-pkg"), "v1.0.1")
            self.assertEqual(resolved.get("example.com/another-fork"), "v2.0.0-rc1")
            self.assertNotIn("example.com/another-replaced-pkg", resolved)
        finally:
            os.remove(tmp_path)

    def test_parser_advanced_edge_cases(self):
        import json
        import tempfile
        
        # 1. Yarn Multi-specifiers and Scoped Packages
        yarn_content = (
            "\"@babel/core@npm:^7.12.3, @babel/core@npm:^7.12.9\":\n"
            "  version: 7.12.9\n"
            "  dependencies:\n"
            "    \"@babel/code-frame\": \"npm:^7.10.4\"\n"
            "\n"
            "lodash@^4.17.20, lodash@^4.17.21:\n"
            "  version \"4.17.21\"\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock", encoding="utf-8") as tmp:
            tmp.write(yarn_content)
            tmp_path = tmp.name
        try:
            resolved, parents, _integrity = kevlar.parse_yarn_lock(tmp_path)
            self.assertEqual(resolved.get("@babel/core"), ["7.12.9"])
            self.assertEqual(resolved.get("lodash"), ["4.17.21"])
            self.assertIn("@babel/core", parents.get("@babel/code-frame", []))
        finally:
            os.remove(tmp_path)
            
        # 2. PNPM Peer Dependency Brackets
        pnpm_content = (
            "lockfileVersion: '6.0'\n"
            "packages:\n"
            "  /foo@1.0.0(bar@2.0.0)(baz@3.0.0):\n"
            "    resolution: {integrity: sha512-abc}\n"
            "    dependencies:\n"
            "      bar: 2.0.0\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml", encoding="utf-8") as tmp:
            tmp.write(pnpm_content)
            tmp_path = tmp.name
        try:
            resolved, parents, _integrity = kevlar.parse_pnpm_lock(tmp_path)
            self.assertEqual(resolved.get("foo"), ["1.0.0"])
        finally:
            os.remove(tmp_path)

        # 3. Gemfile.lock Multiple Sections (GEM, GIT, PATH)
        gemfile_content = (
            "GIT\n"
            "  remote: https://github.com/rails/rails.git\n"
            "  revision: 1234abcd\n"
            "  specs:\n"
            "    rails (6.1.4)\n"
            "      activesupport (= 6.1.4)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    activesupport (6.1.4)\n"
            "    json (2.5.1)\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock") as tmp:
            tmp.write(gemfile_content)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_gemfile_lock(tmp_path)
            self.assertEqual(resolved.get("rails"), "6.1.4")
            self.assertEqual(resolved.get("activesupport"), "6.1.4")
            self.assertEqual(resolved.get("json"), "2.5.1")
            self.assertIn("rails", parents.get("activesupport", []))
        finally:
            os.remove(tmp_path)

        # 4. Gradle Lockfile Multi-Configurations
        gradle_content = (
            "# Gradle lockfile\n"
            "org.slf4j:slf4j-api:1.7.30=compileClasspath,runtimeClasspath\n"
            "org.apache.commons:commons-lang3:3.12.0=annotationProcessor,compileClasspath,runtimeClasspath\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lockfile") as tmp:
            tmp.write(gradle_content)
            tmp_path = tmp.name
        try:
            resolved = kevlar.parse_gradle_lockfile(tmp_path)
            self.assertEqual(resolved.get("org.slf4j:slf4j-api"), "1.7.30")
            self.assertEqual(resolved.get("org.apache.commons:commons-lang3"), "3.12.0")
        finally:
            os.remove(tmp_path)

        # 5. Composer lock skipping platform requirements
        composer_data = {
            "packages": [
                {
                    "name": "guzzlehttp/guzzle",
                    "version": "v7.4.1",
                    "require": {
                        "php": "^7.2.5 || ^8.0",
                        "ext-json": "*",
                        "psr/http-client": "^1.0"
                    }
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
            json.dump(composer_data, tmp)
            tmp_path = tmp.name
        try:
            resolved, parents = kevlar.parse_composer_lock(tmp_path)
            self.assertEqual(resolved.get("guzzlehttp/guzzle"), ["7.4.1"])
            self.assertIn("guzzlehttp/guzzle", parents.get("psr/http-client", []))
            self.assertNotIn("php", parents)
            self.assertNotIn("ext-json", parents)
        finally:
            os.remove(tmp_path)

    def test_parse_cargo_lock(self):
        import tempfile
        content = (
            "version = 4\n"
            "\n"
            "[[package]]\n"
            "name = \"serde\"\n"
            "version = \"1.0.130\"\n"
            "dependencies = [\n"
            " \"serde_derive 1.0.130\",\n"
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

    def test_check_ruby_package_404_local(self):
        import urllib.error
        from unittest.mock import patch
        target = {
            "name": "capybara_accessible_selectors",
            "declared": "0.10.0",
            "installed": ["0.10.0"]
        }
        with patch("kevlar.safe_urlopen", side_effect=urllib.error.HTTPError("url", 404, "Not Found", {}, None)):
            res = kevlar.check_ruby_package(target)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["status"], "local")
            self.assertEqual(res[0]["latest"], "Local")
            self.assertIsNone(res[0]["error"])

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
            "junit = { require = \"4.13.2\" }\n"
            "\n"
            "[libraries]\n"
            "groovy-core = { module = \"org.codehaus.groovy:groovy\", version.ref = \"groovy\" }\n"
            "groovy-json = \"org.codehaus.groovy:groovy-json:3.0.5\"\n"
            "junit-api = { group = \"junit\", name = \"junit\", version.ref = \"junit\" }\n"
            "mock-lib = { group = \"org.mock\", name = \"mock\", version = { require = \"1.2.3\" } }\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".toml") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved = kevlar.parse_libs_versions_toml(tmp_path)
            self.assertEqual(resolved.get("org.codehaus.groovy:groovy"), "3.0.5")
            self.assertEqual(resolved.get("org.codehaus.groovy:groovy-json"), "3.0.5")
            self.assertEqual(resolved.get("junit:junit"), "4.13.2")
            self.assertEqual(resolved.get("org.mock:mock"), "1.2.3")
        finally:
            os.remove(tmp_path)

    def test_apply_suppressions_project_path_lookup(self):
        import json
        import shutil
        import tempfile
        
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
        import io
        import json
        import shutil
        import tempfile
        
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
            
            remed_dict = results_for_remed[0].get("remediation")
            self.assertIsNotNone(remed_dict)
            remed = remed_dict["major"] or remed_dict["safe"]
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
        import json
        import tempfile
        
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
        import urllib.request
        from unittest.mock import MagicMock, patch
        
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
        import json
        from unittest.mock import MagicMock, patch

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
        import json
        from unittest.mock import MagicMock, patch

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
        import json
        import sys
        from unittest.mock import MagicMock, patch

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
        import io
        from urllib.error import HTTPError
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

    def test_pseudo_version_and_none_latest_up_to_date(self):
        # 1. Test classify_update with pseudo-versions and matching/clean versions
        self.assertEqual(kevlar.classify_update("v0.0.0-20260525132238-948f4557a654", "0.0.0-20260525132238-948f4557a654"), "up-to-date")
        self.assertEqual(kevlar.classify_update("0.0.0-20260525132238-948f4557a654", "0.0.0"), "up-to-date")
        self.assertEqual(kevlar.classify_update("v1.2.3", "1.2.3"), "up-to-date")
        
        # 2. Test determine_update_type when latest_absolute is None, 0.0.0, or matches installed pseudo-version
        self.assertEqual(kevlar.determine_update_type("v0.0.0-20260525132238-948f4557a654", None, None), "up-to-date")
        self.assertEqual(kevlar.determine_update_type("v0.0.0-20260525132238-948f4557a654", "0.0.0", "0.0.0"), "up-to-date")
        self.assertEqual(kevlar.determine_update_type("v0.0.0-20260525132238-948f4557a654", "v0.0.0-20260525132238-948f4557a654", "v0.0.0-20260525132238-948f4557a654"), "up-to-date")
        
    @patch("urllib.request.urlopen")
    def test_check_go_package_pseudo_version_status(self, mock_urlopen):
        # Mock empty list returned by Go proxy
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b""
        
        target = {
            "name": "github.com/charmbracelet/ultraviolet",
            "declared": "v0.0.0-20260525132238-948f4557a654",
            "installed": ["v0.0.0-20260525132238-948f4557a654"]
        }
        res = kevlar.check_go_package(target)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["status"], "up-to-date")
        self.assertIsNone(res[0]["latest"])
        self.assertIsNone(res[0]["latest_absolute"])

    def test_parse_go_mod_advanced_directives(self):
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            go_mod_content = (
                "module github.com/test/project\n\n"
                "go 1.24\n\n"
                "require (\n"
                "    github.com/gin-gonic/gin v1.9.1\n"
                "    github.com/sirupsen/logrus v1.9.0 // indirect\n"
                ")\n\n"
                "replace github.com/gin-gonic/gin => ../local-gin\n\n"
                "exclude (\n"
                "    github.com/sirupsen/logrus v1.9.1\n"
                ")\n\n"
                "retract v1.0.0\n\n"
                "tool golang.org/x/tools/cmd/stringer\n"
            )
            mod_path = os.path.join(temp_dir, "go.mod")
            with open(mod_path, "w", encoding="utf-8") as f:
                f.write(go_mod_content)

            deps, dev_deps, local_reps, ex_vers, ret_vers = kevlar.parse_go_mod(mod_path)
            self.assertIn("github.com/gin-gonic/gin", deps)
            self.assertIn("github.com/sirupsen/logrus", dev_deps)
            self.assertIn("golang.org/x/tools/cmd/stringer", dev_deps)
            self.assertEqual(local_reps.get("github.com/gin-gonic/gin"), "../local-gin")
            self.assertIn("v1.9.1", ex_vers.get("github.com/sirupsen/logrus", set()))
            self.assertIn("v1.0.0", ret_vers.get("_global", set()))

            # Test go.work workspace parsing
            go_work_content = (
                "go 1.24\n\n"
                "use (\n"
                "    .\n"
                ")\n"
            )
            work_path = os.path.join(temp_dir, "go.work")
            with open(work_path, "w", encoding="utf-8") as f:
                f.write(go_work_content)

            modules = kevlar.parse_go_work(work_path)
            self.assertEqual(len(modules), 1)
            self.assertEqual(os.path.abspath(mod_path), os.path.abspath(modules[0]))
        finally:
            shutil.rmtree(temp_dir)

    def test_excluded_version_vulnerability_fix_warning(self):
        import shutil
        import tempfile
        from unittest.mock import patch

        temp_dir = tempfile.mkdtemp()
        try:
            go_mod_content = (
                "module github.com/test/excluded-vuln\n\n"
                "go 1.22\n\n"
                "require (\n"
                "    github.com/vulnerable/pkg v1.0.0\n"
                ")\n\n"
                "exclude (\n"
                "    github.com/vulnerable/pkg v1.0.1\n"
                ")\n"
            )
            mod_path = os.path.join(temp_dir, "go.mod")
            with open(mod_path, "w", encoding="utf-8") as f:
                f.write(go_mod_content)

            import argparse
            args = argparse.Namespace(path=temp_dir, concurrent=1, vuls=True)

            with patch("kevlar.check_all_go_targets") as mock_check, \
                 patch("kevlar.check_osv_vulnerabilities") as mock_osv:
                mock_check.return_value = [{
                    "name": "github.com/vulnerable/pkg",
                    "declared": "v1.0.0",
                    "installed": "v1.0.0",
                    "latest": "v1.0.0",
                    "latest_same_major": "v1.0.0",
                    "latest_absolute": "v1.0.0",
                    "status": "up-to-date",
                    "deprecated": None,
                    "error": None,
                    "repo_url": None,
                    "compare_url": None,
                    "releases_url": None,
                    "dep_type": "Direct"
                }]
                mock_osv.return_value = {
                    ("github.com/vulnerable/pkg", "v1.0.0"): [{
                        "id": "GHSA-1234-5678-9012",
                        "summary": "Sample Vulnerability",
                        "severity": "HIGH"
                    }]
                }

                results, _pkg_data, _ = kevlar.run_go_checker(args)
                self.assertEqual(len(results), 1)
                self.assertIn("excluded_warning", results[0])
                self.assertIn("v1.0.1", results[0]["excluded_warning"])
                self.assertIn("may contain fix patches", results[0]["excluded_warning"])
        finally:
            shutil.rmtree(temp_dir)

    def test_parse_go_sum_and_verify_checksums(self):
        import shutil
        import tempfile
        from unittest.mock import patch

        temp_dir = tempfile.mkdtemp()
        try:
            sum_content = (
                "github.com/fatih/color v1.19.0 h1:Zp3PiM21/9Ld6FzSKyL5c/BULoe/ONr9KlbYVOfG8+w=\n"
                "github.com/fatih/color v1.19.0/go.mod h1:zNk67I0ZUT1bEGsSGyCZYZNrHuTkJJB+r6Q9VuMi0LE=\n"
            )
            sum_path = os.path.join(temp_dir, "go.sum")
            with open(sum_path, "w", encoding="utf-8") as f:
                f.write(sum_content)

            parsed = kevlar.parse_go_sum(sum_path)
            self.assertIn(("github.com/fatih/color", "v1.19.0"), parsed)
            self.assertEqual(parsed[("github.com/fatih/color", "v1.19.0")], "h1:Zp3PiM21/9Ld6FzSKyL5c/BULoe/ONr9KlbYVOfG8+w=")

            results = [{
                "name": "github.com/fatih/color",
                "installed": "v1.19.0",
                "declared": "v1.19.0"
            }, {
                "name": "github.com/missing/pkg",
                "installed": "v1.0.0",
                "declared": "v1.0.0"
            }]

            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.return_value.__enter__.return_value.read.return_value = (
                    b"51441162\n"
                    b"github.com/fatih/color v1.19.0 h1:Zp3PiM21/9Ld6FzSKyL5c/BULoe/ONr9KlbYVOfG8+w=\n"
                )
                kevlar.verify_go_checksums(results, sum_path, max_workers=1)

            self.assertTrue(results[0].get("checksum_verified"))
            self.assertTrue(results[1].get("missing_checksum"))
        finally:
            shutil.rmtree(temp_dir)

    def test_generate_remediation_diff_cpm_fallback(self):
        import shutil
        import tempfile
        
        temp_dir = tempfile.mkdtemp()
        try:
            # 1. Project file reference without inline version (CPM active)
            csproj_content = '<PackageReference Include="System.Text.Json" />\n'
            csproj_path = os.path.join(temp_dir, "test.csproj")
            with open(csproj_path, "w", encoding="utf-8") as f:
                f.write(csproj_content)
                
            diff = kevlar.generate_remediation_diff(
                csproj_path, 
                line_index=1, 
                declared_ver="8.0.0", 
                latest_ver="10.0.10", 
                tech="nuget", 
                package_name="System.Text.Json"
            )
            self.assertIsNone(diff)
            
            # 2. Project file reference with inline version
            csproj_with_ver = '<PackageReference Include="System.Text.Json" Version="8.0.0" />\n'
            csproj_path_ver = os.path.join(temp_dir, "test_ver.csproj")
            with open(csproj_path_ver, "w", encoding="utf-8") as f:
                f.write(csproj_with_ver)
                
            diff_ver = kevlar.generate_remediation_diff(
                csproj_path_ver, 
                line_index=1, 
                declared_ver="8.0.0", 
                latest_ver="10.0.10", 
                tech="nuget", 
                package_name="System.Text.Json"
            )
            self.assertIsNotNone(diff_ver)
            self.assertIn('<span class="diff-add-chunk">10.0.10</span>', diff_ver["suggested_code"][0]["html"])
            self.assertIn("System.Text.Json", diff_ver["suggested_code"][0]["html"])
            
            # 2b. Cargo.toml semver specifier compatible diff (e.g. declared 1.3.3 vs Cargo.toml 1.0)
            cargo_content = '[dependencies]\nbincode = "1.0"\n'
            cargo_path = os.path.join(temp_dir, "Cargo.toml")
            with open(cargo_path, "w", encoding="utf-8") as f:
                f.write(cargo_content)
                
            diff_cargo = kevlar.generate_remediation_diff(
                cargo_path,
                line_index=2,
                declared_ver="1.3.3",
                latest_ver="3.0.0",
                tech="rust",
                package_name="bincode"
            )
            self.assertIsNotNone(diff_cargo)
            self.assertIn('<span class="diff-add-chunk">3.0.0</span>', diff_cargo["suggested_code"][1]["html"])
            
            # 3. Test find_manifest_files parent resolution for nuget props file
            sub_dir = os.path.join(temp_dir, "src", "Project")
            os.makedirs(sub_dir, exist_ok=True)
            
            sub_csproj = os.path.join(sub_dir, "test.csproj")
            with open(sub_csproj, "w", encoding="utf-8") as f:
                f.write(csproj_content)
                
            props_path = os.path.join(temp_dir, "Directory.Packages.props")
            with open(props_path, "w", encoding="utf-8") as f:
                f.write('<PackageVersion Include="System.Text.Json" Version="8.0.0" />\n')
                
            manifests = kevlar.find_manifest_files(sub_dir, "nuget")
            self.assertIn(props_path, [os.path.abspath(m) for m in manifests])
            self.assertIn(sub_csproj, [os.path.abspath(m) for m in manifests])

            # Ensure ignored directories (like node_modules, .git) are skipped
            ignored_sub = os.path.join(temp_dir, "node_modules", "nested")
            os.makedirs(ignored_sub, exist_ok=True)
            ignored_file = os.path.join(ignored_sub, "ignored.csproj")
            with open(ignored_file, "w", encoding="utf-8") as f:
                f.write(csproj_content)
            all_manifests = [os.path.abspath(m) for m in kevlar.find_manifest_files(temp_dir, "nuget")]
            self.assertNotIn(os.path.abspath(ignored_file), all_manifests)
            
            # 4. Test placeholders / properties matching & resolution to definition lines
            maven_pom = (
                '<project>\n'
                '    <properties>\n'
                '        <org.spring-security.version>3.2.9.RELEASE</org.spring-security.version>\n'
                '    </properties>\n'
                '    <dependencies>\n'
                '        <dependency>\n'
                '            <groupId>org.springframework.security</groupId>\n'
                '            <artifactId>spring-security-web</artifactId>\n'
                '            <version>${org.spring-security.version}</version>\n'
                '        </dependency>\n'
                '    </dependencies>\n'
                '</project>\n'
            )
            pom_path = os.path.join(temp_dir, "pom.xml")
            with open(pom_path, "w", encoding="utf-8") as f:
                f.write(maven_pom)
            diff_maven = kevlar.generate_remediation_diff(
                pom_path, line_index=8, declared_ver="3.2.9.RELEASE", latest_ver="3.2.10.RELEASE", tech="maven", package_name="spring-security-web"
            )
            self.assertIsNotNone(diff_maven)
            self.assertEqual(diff_maven["line_number"], 3)  # Resolved to properties line
            self.assertTrue(any('<span class="diff-add-chunk">3.2.10.RELEASE</span>' in item["html"] for item in diff_maven["suggested_code"]))
            
            # Test version mismatch verification (should skip this manifest file/property definition)
            diff_maven_mismatch = kevlar.generate_remediation_diff(
                pom_path, line_index=8, declared_ver="4.0.9.RELEASE", latest_ver="4.0.10.RELEASE", tech="maven", package_name="spring-security-web"
            )
            self.assertIsNone(diff_maven_mismatch)
            
            gradle_build = (
                'ext {\n'
                '    springVersion = "4.3.5.RELEASE"\n'
                '}\n'
                'implementation "org.springframework:spring-web:$springVersion"\n'
            )
            gradle_path = os.path.join(temp_dir, "build.gradle")
            with open(gradle_path, "w", encoding="utf-8") as f:
                f.write(gradle_build)
            diff_gradle = kevlar.generate_remediation_diff(
                gradle_path, line_index=4, declared_ver="4.3.5.RELEASE", latest_ver="4.3.30.RELEASE", tech="gradle", package_name="org.springframework:spring-web"
            )
            self.assertIsNotNone(diff_gradle)
            self.assertEqual(diff_gradle["line_number"], 2)  # Resolved to ext block variable line
            self.assertTrue(any('<span class="diff-add-chunk">4.3.30.RELEASE</span>' in item["html"] for item in diff_gradle["suggested_code"]))
            
        finally:
            shutil.rmtree(temp_dir)

    def test_npm_checker_only_engines(self):
        import json
        import shutil
        import tempfile
        import types

        temp_dir = tempfile.mkdtemp()
        try:
            package_json_content = {
                "name": "engines-only-app",
                "version": "1.0.0",
                "engines": {
                    "node": ">=14"
                }
            }
            with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as f:
                json.dump(package_json_content, f, indent=2)

            args = types.SimpleNamespace(
                path=temp_dir,
                all=False,
                concurrent=5,
                vuls=False,
                suppress=None
            )

            results, _pkg_data, _elapsed = kevlar.run_npm_checker(args)
            self.assertIsNotNone(results)
            self.assertTrue(len(results) > 0)
            engine_item = next((r for r in results if r.get("name") == "node" and r.get("is_engine")), None)
            self.assertIsNotNone(engine_item)
            self.assertEqual(engine_item["declared"], ">=14")
            self.assertIn(engine_item["status"], ("error", "minor"))
            
            engine_item["project_path"] = temp_dir
            engine_item["technology"] = "npm"
            kevlar.populate_remediation_recommendations(results, temp_dir)
            rem = engine_item.get("remediation")
            self.assertIsNotNone(rem)
            self.assertIsNotNone(rem.get("options"))
            options = rem["options"]
            self.assertGreaterEqual(len(options), 3)
            labels = [opt["label"] for opt in options]
            self.assertIn("Version 24", labels)
            self.assertIn("Version 26", labels)
            self.assertIn("Version 24 o 26", labels)
        finally:
            shutil.rmtree(temp_dir)

    def test_remediation_diff_identical_version_skipped(self):
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            pom_content = (
                '<project>\n'
                '    <dependencies>\n'
                '        <dependency>\n'
                '            <groupId>log4j</groupId>\n'
                '            <artifactId>log4j</artifactId>\n'
                '            <version>1.2.17</version>\n'
                '            <scope>test</scope>\n'
                '        </dependency>\n'
                '    </dependencies>\n'
                '</project>\n'
            )
            pom_path = os.path.join(temp_dir, "pom.xml")
            with open(pom_path, "w", encoding="utf-8") as f:
                f.write(pom_content)

            # 1. generate_remediation_diff should return None when target version equals current version
            diff = kevlar.generate_remediation_diff(
                pom_path,
                line_index=6,
                declared_ver="1.2.17",
                latest_ver="1.2.17",
                tech="maven",
                package_name="log4j"
            )
            self.assertIsNone(diff)

            # 2. populate_remediation_recommendations should not attach remediation when latest version equals current version
            results = [{
                "name": "log4j",
                "declared": "1.2.17",
                "installed": "1.2.17",
                "latest_same_major": "1.2.17",
                "latest_absolute": "1.2.17",
                "latest": "1.2.17",
                "status": "up-to-date",
                "vulnerabilities": [{"id": "GHSA-1234"}],
                "technology": "maven",
                "project_path": temp_dir
            }]
            kevlar.populate_remediation_recommendations(results, temp_dir)
            self.assertIsNone(results[0].get("remediation"))
        finally:
            shutil.rmtree(temp_dir)

    def test_maven_parent_pom_property_resolution(self):
        """Test that parse_maven_pom resolves properties defined in parent pom.xml when parsing child modules."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            # Create parent pom.xml
            parent_pom = (
                '<project>\n'
                '    <groupId>com.example</groupId>\n'
                '    <artifactId>parent</artifactId>\n'
                '    <version>1.0.0</version>\n'
                '    <properties>\n'
                '        <commons.fileupload.version>1.3.3</commons.fileupload.version>\n'
                '    </properties>\n'
                '</project>\n'
            )
            with open(os.path.join(temp_dir, "pom.xml"), "w", encoding="utf-8") as f:
                f.write(parent_pom)

            # Create child submodule pom.xml
            child_dir = os.path.join(temp_dir, "child")
            os.makedirs(child_dir, exist_ok=True)
            child_pom = (
                '<project>\n'
                '    <parent>\n'
                '        <groupId>com.example</groupId>\n'
                '        <artifactId>parent</artifactId>\n'
                '        <version>1.0.0</version>\n'
                '    </parent>\n'
                '    <artifactId>child</artifactId>\n'
                '    <dependencies>\n'
                '        <dependency>\n'
                '            <groupId>commons-fileupload</groupId>\n'
                '            <artifactId>commons-fileupload</artifactId>\n'
                '            <version>${commons.fileupload.version}</version>\n'
                '        </dependency>\n'
                '    </dependencies>\n'
                '</project>\n'
            )
            child_pom_path = os.path.join(child_dir, "pom.xml")
            with open(child_pom_path, "w", encoding="utf-8") as f:
                f.write(child_pom)

            deps = kevlar.parse_maven_pom(child_pom_path)
            self.assertEqual(deps.get("commons-fileupload:commons-fileupload"), "1.3.3")
        finally:
            shutil.rmtree(temp_dir)

    def test_maven_transitive_dependency_resolution(self):
        """Test that resolve_maven_transitive_dependencies fetches remote POMs and resolves child transitive dependencies."""
        from unittest.mock import patch

        parent_pom_xml = (
            '<project>\n'
            '  <groupId>org.example</groupId>\n'
            '  <artifactId>parent-lib</artifactId>\n'
            '  <version>1.0.0</version>\n'
            '  <dependencies>\n'
            '    <dependency>\n'
            '      <groupId>org.example</groupId>\n'
            '      <artifactId>child-lib</artifactId>\n'
            '      <version>2.0.0</version>\n'
            '      <scope>compile</scope>\n'
            '    </dependency>\n'
            '    <dependency>\n'
            '      <groupId>org.example</groupId>\n'
            '      <artifactId>test-lib</artifactId>\n'
            '      <version>1.0.0</version>\n'
            '      <scope>test</scope>\n'
            '    </dependency>\n'
            '  </dependencies>\n'
            '</project>'
        )

        def mock_fetch(group_id, artifact_id, version, *args, **kwargs):
            if group_id == "org.example" and artifact_id == "parent-lib":
                return kevlar.safe_et_fromstring(parent_pom_xml)
            return None

        with patch("kevlar.fetch_remote_maven_pom", side_effect=mock_fetch):
            direct_deps = {"org.example:parent-lib": "1.0.0"}
            all_deps, required_by, dep_types = kevlar.resolve_maven_transitive_dependencies(direct_deps)

            self.assertIn("org.example:parent-lib", all_deps)
            self.assertIn("org.example:child-lib", all_deps)
            self.assertNotIn("org.example:test-lib", all_deps)
            self.assertEqual(dep_types["org.example:parent-lib"], "Direct")
            self.assertEqual(dep_types["org.example:child-lib"], "Transitive")
            self.assertIn("org.example:parent-lib", required_by["org.example:child-lib"])

    def test_parse_requirements_txt_relative_inclusion(self):
        """Test that parse_requirements_txt resolves included requirements files and ignores path strings like '..'."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            root_req = os.path.join(temp_dir, "requirements.txt")
            with open(root_req, "w", encoding="utf-8") as f:
                f.write("requests==2.28.1\n")

            sub_dir = os.path.join(temp_dir, "sub")
            os.makedirs(sub_dir, exist_ok=True)
            sub_req = os.path.join(sub_dir, "requirements.txt")
            with open(sub_req, "w", encoding="utf-8") as f:
                f.write("../requirements.txt\n")

            deps, _ = kevlar.parse_requirements_txt(sub_req, base_dir=temp_dir)
            self.assertIn("requests", deps)
            self.assertNotIn("..", deps)
        finally:
            shutil.rmtree(temp_dir)

    def test_parse_requirements_txt_path_traversal_prevented(self):
        """Test that parse_requirements_txt blocks inclusions escaping base_dir."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        outside_dir = tempfile.mkdtemp()
        try:
            outside_req = os.path.join(outside_dir, "outside_req.txt")
            with open(outside_req, "w", encoding="utf-8") as f:
                f.write("secret-package==1.0.0\n")

            rel_path_to_outside = os.path.relpath(outside_req, temp_dir)
            main_req = os.path.join(temp_dir, "requirements.txt")
            with open(main_req, "w", encoding="utf-8") as f:
                f.write(f"-r {rel_path_to_outside}\n")

            deps, _ = kevlar.parse_requirements_txt(main_req, base_dir=temp_dir)
            self.assertNotIn("secret-package", deps)
        finally:
            shutil.rmtree(temp_dir)
            shutil.rmtree(outside_dir)


    def test_no_show_console_flag(self):
        """Test that print_results_table returns without printing when no_show_console is True."""
        import io
        import sys

        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        try:
            results = [{
                "name": "log4j",
                "declared": "1.2.17",
                "installed": "1.2.17",
                "latest": "2.17.1",
                "status": "major",
                "vulnerabilities": [],
                "deprecated": None
            }]
            kevlar.print_results_table(results, {}, show_all=True, no_show_console=True)
            self.assertEqual(captured_output.getvalue(), "")
        finally:
            sys.stdout = old_stdout

    def test_remediation_diff_missing_manifest_entry(self):
        """Test that populate_remediation_recommendations generates an addition diff for direct dependencies missing from manifest."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            pkg_json = '{\n  "name": "test-pkg",\n  "dependencies": {\n    "express": "^4.18.0"\n  }\n}\n'
            pkg_json_path = os.path.join(temp_dir, "package.json")
            with open(pkg_json_path, "w", encoding="utf-8") as f:
                f.write(pkg_json)

            results = [{
                "name": "drizzle-orm",
                "declared": "",
                "installed": "0.38.4",
                "latest_same_major": "0.45.2",
                "latest_absolute": "0.45.2",
                "latest": "0.45.2",
                "status": "minor",
                "vulnerabilities": ["GHSA-gpj5-g38j-94v9"],
                "technology": "npm",
                "dep_type": "Direct",
                "project_path": temp_dir
            }]

            kevlar.populate_remediation_recommendations(results, temp_dir)

            rem = results[0].get("remediation")
            self.assertIsNotNone(rem)
            self.assertTrue(results[0].get("manifest_missing"))
            self.assertTrue(rem.get("manifest_missing"))
            safe_diff = rem.get("safe") or rem.get("major")
            self.assertIsNotNone(safe_diff)
            self.assertTrue(safe_diff.get("is_addition"))
            self.assertIn("drizzle-orm", str(safe_diff.get("suggested_code")))
        finally:
            shutil.rmtree(temp_dir)

    # --------------------------------------------------------------------------
    # RUST ECOSYSTEM TESTS
    # --------------------------------------------------------------------------
    def test_find_rust_files_and_parse_cargo_toml_and_lock(self):
        """Test finding Rust files and parsing Cargo.toml and Cargo.lock."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            # 1. Test find_rust_files
            toml_path, lock_path = kevlar.find_rust_files(temp_dir)
            self.assertIsNone(toml_path)
            self.assertIsNone(lock_path)

            cargo_toml_content = """
            [package]
            name = "my_crate"
            version = "0.1.0"

            [dependencies]
            serde = "1.0.190"
            tokio = { version = "1.32.0", features = ["full"] }
            local_lib = { path = "../local_lib" }

            [dev-dependencies]
            pytest-rs = "^0.5.0"

            [workspace.dependencies]
            shared_crate = "2.0.0"
            """

            cargo_lock_content = """
            version = 3

            [[package]]
            name = "my_crate"
            version = "0.1.0"
            dependencies = [
             "serde",
             "tokio",
            ]

            [[package]]
            name = "serde"
            version = "1.0.195"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "tokio"
            version = "1.35.1"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            dependencies = [
             "bytes",
             "pin-project-lite",
            ]

            [[package]]
            name = "bytes"
            version = "1.5.0"

            [[package]]
            name = "pin-project-lite"
            version = "0.2.13"
            """

            real_toml = os.path.join(temp_dir, "Cargo.toml")
            real_lock = os.path.join(temp_dir, "Cargo.lock")
            with open(real_toml, "w", encoding="utf-8") as f:
                f.write(cargo_toml_content)
            with open(real_lock, "w", encoding="utf-8") as f:
                f.write(cargo_lock_content)

            found_toml, found_lock = kevlar.find_rust_files(temp_dir)
            self.assertEqual(found_toml, real_toml)
            self.assertEqual(found_lock, real_lock)

            # 2. Test parse_cargo_toml returns a set of direct dependency names
            direct_deps = kevlar.parse_cargo_toml(found_toml)
            self.assertIn("serde", direct_deps)
            self.assertIn("tokio", direct_deps)
            self.assertIn("pytest-rs", direct_deps)
            self.assertIn("shared_crate", direct_deps)
            self.assertIn("local_lib", direct_deps)

            # 3. Test parse_cargo_lock returns resolved dict and parents dict
            resolved, parents = kevlar.parse_cargo_lock(found_lock)
            self.assertEqual(resolved.get("serde"), ["1.0.195"])
            self.assertEqual(resolved.get("tokio"), ["1.35.1"])
            self.assertEqual(resolved.get("bytes"), ["1.5.0"])
            self.assertEqual(resolved.get("pin-project-lite"), ["0.2.13"])
            self.assertIn("tokio", parents.get("bytes", set()))
            self.assertIn("tokio", parents.get("pin-project-lite", set()))

            # 4. Test get_crates_index_url
            self.assertTrue(kevlar.get_crates_index_url("a").endswith("/1/a"))
            self.assertTrue(kevlar.get_crates_index_url("ab").endswith("/2/ab"))
            self.assertTrue(kevlar.get_crates_index_url("abc").endswith("/3/a/abc"))
            self.assertTrue(kevlar.get_crates_index_url("abcd").endswith("/ab/cd/abcd"))
            self.assertTrue(kevlar.get_crates_index_url("serde").endswith("/se/rd/serde"))
        finally:
            shutil.rmtree(temp_dir)

    def test_check_rust_package_and_run_rust_checker(self):
        """Test check_rust_package with sparse index and run_rust_checker orchestration."""
        import shutil
        import tempfile
        import types
        from unittest.mock import MagicMock, patch

        target = {
            "name": "serde",
            "declared": "1.0.190",
            "installed": ["1.0.190"],
        }

        sparse_lines = (
            '{"name":"serde","vers":"1.0.189","yanked":false}\n'
            '{"name":"serde","vers":"1.0.190","yanked":false}\n'
            '{"name":"serde","vers":"1.0.191","yanked":true}\n'
            '{"name":"serde","vers":"1.0.195","yanked":false}\n'
            '{"name":"serde","vers":"2.0.0","yanked":false}\n'
        )

        with patch("kevlar.safe_urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.read.return_value = sparse_lines.encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_url.return_value = mock_resp

            res = kevlar.check_rust_package(target)
            self.assertEqual(len(res), 1)
            row = res[0]
            self.assertEqual(row["name"], "serde")
            self.assertEqual(row["status"], "patch-major")
            self.assertEqual(row["latest_same_major"], "1.0.195")
            self.assertEqual(row["latest_absolute"], "2.0.0")

        # Test run_rust_checker
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "Cargo.toml"), "w", encoding="utf-8") as f:
                f.write('[package]\nname = "demo"\nversion = "0.1.0"\n[dependencies]\nserde = "1.0.190"\n')
            with open(os.path.join(temp_dir, "Cargo.lock"), "w", encoding="utf-8") as f:
                f.write('version = 3\n[[package]]\nname = "serde"\nversion = "1.0.190"\n')

            args = types.SimpleNamespace(path=temp_dir, all=True, concurrent=2, vuls=False)
            with patch("kevlar.safe_urlopen") as mock_url:
                mock_resp = MagicMock()
                mock_resp.read.return_value = sparse_lines.encode("utf-8")
                mock_resp.__enter__.return_value = mock_resp
                mock_url.return_value = mock_resp

                results, pkg_data, _elapsed = kevlar.run_rust_checker(args)
                self.assertIsNotNone(results)
                self.assertEqual(len(results), 1)
                self.assertIn("serde", pkg_data["all_direct"])
        finally:
            shutil.rmtree(temp_dir)

    def test_cargo_workspace_resolution(self):
        """Test Cargo workspace dependency resolution with root Cargo.lock and workspace.dependencies."""
        import shutil
        import tempfile
        import types
        from unittest.mock import MagicMock, patch

        temp_dir = tempfile.mkdtemp()
        try:
            # 1. Setup workspace structure:
            # temp_dir/Cargo.toml (workspace root)
            # temp_dir/Cargo.lock (workspace lockfile)
            # temp_dir/crates/sub_pkg/Cargo.toml (sub-crate referencing workspace)
            root_toml_content = """
            [workspace]
            members = ["crates/sub_pkg"]

            [workspace.dependencies]
            serde = { version = "1.0.190", features = ["derive"] }
            tokio = "1.32.0"
            local_helper = { path = "crates/helper" }
            """

            root_lock_content = """
            version = 3
            [[package]]
            name = "sub_pkg"
            version = "0.1.0"
            dependencies = ["serde", "tokio", "app_test_support"]

            [[package]]
            name = "serde"
            version = "1.0.195"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "tokio"
            version = "1.35.1"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "app_test_support"
            version = "0.0.0"
            """

            sub_dir = os.path.join(temp_dir, "crates", "sub_pkg")
            os.makedirs(sub_dir, exist_ok=True)

            sub_toml_content = """
            [package]
            name = "sub_pkg"
            version = "0.1.0"

            [dependencies]
            serde = { workspace = true }
            tokio = { workspace = true }
            app_test_support = { workspace = true }
            """

            root_toml_path = os.path.join(temp_dir, "Cargo.toml")
            root_lock_path = os.path.join(temp_dir, "Cargo.lock")
            sub_toml_path = os.path.join(sub_dir, "Cargo.toml")

            with open(root_toml_path, "w", encoding="utf-8") as f:
                f.write(root_toml_content)
            with open(root_lock_path, "w", encoding="utf-8") as f:
                f.write(root_lock_content)
            with open(sub_toml_path, "w", encoding="utf-8") as f:
                f.write(sub_toml_content)

            # Test upward Cargo.lock discovery
            found_toml, found_lock = kevlar.find_rust_files(sub_dir)
            self.assertEqual(found_toml, sub_toml_path)
            self.assertEqual(found_lock, root_lock_path)

            # Test workspace.dependencies resolution in parse_cargo_toml
            parsed_deps = kevlar.parse_cargo_toml(sub_toml_path)
            self.assertIn("serde", parsed_deps)
            self.assertIn("tokio", parsed_deps)
            self.assertIn("app_test_support", parsed_deps)
            self.assertEqual(parsed_deps["serde"], "1.0.190")
            self.assertEqual(parsed_deps["tokio"], "1.32.0")

            # Test run_rust_checker on sub-crate
            sparse_lines = (
                '{"name":"serde","vers":"1.0.195","yanked":false}\n'
                '{"name":"tokio","vers":"1.35.1","yanked":false}\n'
            )
            args = types.SimpleNamespace(path=sub_dir, all=False, concurrent=2, vuls=False)
            with patch("kevlar.safe_urlopen") as mock_url:
                mock_resp = MagicMock()
                mock_resp.read.return_value = sparse_lines.encode("utf-8")
                mock_resp.__enter__.return_value = mock_resp
                mock_url.return_value = mock_resp

                results, pkg_data, _ = kevlar.run_rust_checker(args)
                self.assertIsNotNone(results)
                self.assertEqual(len(results), 3)
                res_map = {r["name"]: r for r in results}
                self.assertEqual(res_map["serde"]["declared"], "1.0.190")
                self.assertEqual(res_map["serde"]["installed"], "1.0.195")
                self.assertEqual(res_map["tokio"]["declared"], "1.32.0")
                self.assertEqual(res_map["tokio"]["installed"], "1.35.1")
                self.assertEqual(res_map["app_test_support"]["status"], "local")
                self.assertEqual(res_map["app_test_support"]["latest"], "Local")
                self.assertIsNone(res_map["app_test_support"]["error"])
        finally:
            shutil.rmtree(temp_dir)


    # --------------------------------------------------------------------------
    # PHP COMPOSER ECOSYSTEM TESTS
    # --------------------------------------------------------------------------
    def test_find_composer_files_and_parse_composer_json(self):
        """Test finding PHP Composer files and parsing composer.json."""
        import json
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            c_json, c_lock = kevlar.find_composer_files(temp_dir)
            self.assertIsNone(c_json)
            self.assertIsNone(c_lock)

            composer_content = {
                "name": "vendor/project",
                "require": {
                    "php": ">=8.1",
                    "monolog/monolog": "^2.0",
                    "guzzlehttp/guzzle": "~7.4.0",
                },
                "require-dev": {
                    "phpunit/phpunit": "^9.5",
                },
            }

            json_file = os.path.join(temp_dir, "composer.json")
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(composer_content, f)

            found_json, found_lock = kevlar.find_composer_files(temp_dir)
            self.assertEqual(found_json, json_file)
            self.assertIsNone(found_lock)

            direct, dev_direct = kevlar.parse_composer_json(found_json)
            self.assertIn("monolog/monolog", direct)
            self.assertEqual(direct["monolog/monolog"], "^2.0")
            self.assertIn("guzzlehttp/guzzle", direct)
            self.assertEqual(direct["guzzlehttp/guzzle"], "~7.4.0")
            self.assertIn("phpunit/phpunit", dev_direct)
            self.assertEqual(dev_direct["phpunit/phpunit"], "^9.5")
            self.assertNotIn("php", direct)
        finally:
            shutil.rmtree(temp_dir)

    def test_check_composer_package_and_run_composer_checker(self):
        """Test check_composer_package against Packagist API mock and run_composer_checker."""
        import json
        import shutil
        import tempfile
        import types
        from unittest.mock import MagicMock, patch

        target = {
            "name": "monolog/monolog",
            "declared": "^2.0",
            "installed": ["2.8.0"],
        }

        packagist_resp = {
            "packages": {
                "monolog/monolog": [
                    {"version": "2.8.0", "source": {"url": "https://github.com/Seldaek/monolog.git"}},
                    {"version": "2.9.3", "source": {"url": "https://github.com/Seldaek/monolog.git"}},
                    {"version": "3.5.0", "source": {"url": "https://github.com/Seldaek/monolog.git"}},
                ]
            }
        }

        with patch("kevlar.safe_urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(packagist_resp).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_url.return_value = mock_resp

            res = kevlar.check_composer_package(target)
            self.assertEqual(len(res), 1)
            row = res[0]
            self.assertEqual(row["name"], "monolog/monolog")
            self.assertEqual(row["status"], "minor-major")
            self.assertEqual(row["latest_same_major"], "2.9.3")
            self.assertEqual(row["latest_absolute"], "3.5.0")
            self.assertIn("github.com/Seldaek/monolog", row["repo_url"])

        # Test run_composer_checker
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "composer.json"), "w", encoding="utf-8") as f:
                json.dump({"require": {"monolog/monolog": "^2.0"}}, f)
            with open(os.path.join(temp_dir, "composer.lock"), "w", encoding="utf-8") as f:
                json.dump({"packages": [{"name": "monolog/monolog", "version": "2.8.0"}]}, f)

            args = types.SimpleNamespace(path=temp_dir, all=True, concurrent=2, vuls=False)
            with patch("kevlar.safe_urlopen") as mock_url:
                mock_resp = MagicMock()
                mock_resp.read.return_value = json.dumps(packagist_resp).encode("utf-8")
                mock_resp.__enter__.return_value = mock_resp
                mock_url.return_value = mock_resp

                results, _pkg_data, _elapsed = kevlar.run_composer_checker(args)
                self.assertIsNotNone(results)
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["name"], "monolog/monolog")
        finally:
            shutil.rmtree(temp_dir)

    # --------------------------------------------------------------------------
    # RUBY BUNDLER ECOSYSTEM TESTS
    # --------------------------------------------------------------------------
    def test_find_ruby_files_and_parse_gemfile(self):
        """Test finding Ruby files and parsing Gemfile declarations."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            g_file, l_file = kevlar.find_ruby_files(temp_dir)
            self.assertIsNone(g_file)
            self.assertIsNone(l_file)

            gemfile_content = """
            source 'https://rubygems.org'
            ruby '3.2.0'

            gem 'rails', '~> 7.0.4'
            gem "pg", ">= 1.2.0", "< 2.0"
            gem 'puma', require: false

            group :development, :test do
              gem 'rspec-rails', '~> 6.0'
            end
            """

            real_gemfile = os.path.join(temp_dir, "Gemfile")
            with open(real_gemfile, "w", encoding="utf-8") as f:
                f.write(gemfile_content)

            found_gemfile, _found_lock = kevlar.find_ruby_files(temp_dir)
            self.assertEqual(found_gemfile, real_gemfile)

            direct = kevlar.parse_gemfile(found_gemfile)
            self.assertIn("rails", direct)
            self.assertIn("pg", direct)
            self.assertIn("puma", direct)
            self.assertIn("rspec-rails", direct)
            self.assertNotIn("ruby", direct)
        finally:
            shutil.rmtree(temp_dir)

    def test_check_ruby_package_and_run_ruby_checker(self):
        """Test check_ruby_package against RubyGems API mock and run_ruby_checker."""
        import json
        import shutil
        import tempfile
        import types
        from unittest.mock import MagicMock, patch

        target = {
            "name": "rails",
            "declared": "~> 7.0.0",
            "installed": ["7.0.4"],
        }

        gem_versions_resp = [
            {"number": "7.0.4", "prerelease": False, "yanked": False},
            {"number": "7.0.8", "prerelease": False, "yanked": False},
            {"number": "7.1.3", "prerelease": False, "yanked": False},
            {"number": "8.0.0", "prerelease": False, "yanked": False},
        ]
        gem_info_resp = {
            "name": "rails",
            "source_code_uri": "https://github.com/rails/rails",
            "homepage_uri": "https://rubyonrails.org",
        }

        def fake_urlopen(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            mock_resp = MagicMock()
            if "versions" in url:
                mock_resp.read.return_value = json.dumps(gem_versions_resp).encode("utf-8")
            else:
                mock_resp.read.return_value = json.dumps(gem_info_resp).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        with patch("kevlar.safe_urlopen", side_effect=fake_urlopen):
            res = kevlar.check_ruby_package(target)
            self.assertEqual(len(res), 1)
            row = res[0]
            self.assertEqual(row["name"], "rails")
            self.assertEqual(row["status"], "minor-major")
            self.assertEqual(row["latest_same_major"], "7.1.3")
            self.assertEqual(row["latest_absolute"], "8.0.0")
            self.assertEqual(row["repo_url"], "https://github.com/rails/rails")

        # Test run_ruby_checker
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "Gemfile"), "w", encoding="utf-8") as f:
                f.write("source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n")
            with open(os.path.join(temp_dir, "Gemfile.lock"), "w", encoding="utf-8") as f:
                f.write("GEM\n  specs:\n    rails (7.0.4)\nDEPENDENCIES\n  rails (= 7.0.4)\n")

            args = types.SimpleNamespace(path=temp_dir, all=True, concurrent=2, vuls=False)
            with patch("kevlar.safe_urlopen", side_effect=fake_urlopen):
                results, _pkg_data, _elapsed = kevlar.run_ruby_checker(args)
                self.assertIsNotNone(results)
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["name"], "rails")
        finally:
            shutil.rmtree(temp_dir)

    # --------------------------------------------------------------------------
    # .NET NUGET / CPM ECOSYSTEM TESTS
    # --------------------------------------------------------------------------
    def test_find_nuget_files_and_parse_csproj_and_assets(self):
        """Test finding NuGet files, parsing CSProj with CPM, and reading project.assets.json."""
        import json
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            # 1. find_nuget_files returns (found_files, sln_files)
            found_files, sln_files = kevlar.find_nuget_files(temp_dir)
            self.assertEqual(len(found_files), 0)
            self.assertEqual(len(sln_files), 0)

            cpm_xml = """<Project>
              <PropertyGroup>
                <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
              </PropertyGroup>
              <ItemGroup>
                <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
                <PackageVersion Include="Serilog" Version="2.10.0" />
              </ItemGroup>
            </Project>"""

            props_path = os.path.join(temp_dir, "Directory.Packages.props")
            with open(props_path, "w", encoding="utf-8") as f:
                f.write(cpm_xml)

            cpm_versions = kevlar.find_and_parse_cpm_versions(props_path)
            self.assertEqual(cpm_versions.get("Newtonsoft.Json"), "13.0.1")
            self.assertEqual(cpm_versions.get("Serilog"), "2.10.0")

            csproj_xml = """<Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Newtonsoft.Json" />
                <PackageReference Include="Dapper" Version="2.0.123" />
              </ItemGroup>
            </Project>"""

            csproj_path = os.path.join(temp_dir, "MyApp.csproj")
            with open(csproj_path, "w", encoding="utf-8") as f:
                f.write(csproj_xml)

            direct_deps = kevlar.parse_csproj_or_config(temp_dir, cpm_versions)
            self.assertEqual(direct_deps.get("Newtonsoft.Json"), "13.0.1")
            self.assertEqual(direct_deps.get("Dapper"), "2.0.123")

            # project.assets.json
            assets_data = {
                "version": 3,
                "libraries": {
                    "Newtonsoft.Json/13.0.1": {
                        "type": "package",
                    },
                    "Microsoft.CSharp/4.7.0": {
                        "type": "package",
                    },
                },
                "targets": {
                    "net6.0": {
                        "Newtonsoft.Json/13.0.1": {
                            "type": "package",
                            "dependencies": {
                                "Microsoft.CSharp": "4.7.0",
                            },
                        },
                        "Microsoft.CSharp/4.7.0": {
                            "type": "package",
                        },
                    },
                },
            }
            obj_dir = os.path.join(temp_dir, "obj")
            os.makedirs(obj_dir, exist_ok=True)
            assets_path = os.path.join(obj_dir, "project.assets.json")
            with open(assets_path, "w", encoding="utf-8") as f:
                json.dump(assets_data, f)

            resolved, parents = kevlar.parse_project_assets(assets_path)
            self.assertEqual(resolved.get("Newtonsoft.Json"), ["13.0.1"])
            self.assertEqual(resolved.get("Microsoft.CSharp"), ["4.7.0"])
            self.assertIn("Newtonsoft.Json", parents.get("Microsoft.CSharp", []))
        finally:
            shutil.rmtree(temp_dir)

    def test_check_nuget_package_and_run_nuget_checker(self):
        """Test check_nuget_package against NuGet Registration API mock and run_nuget_checker."""
        import json
        import shutil
        import tempfile
        import types
        from unittest.mock import MagicMock, patch

        target = {
            "name": "Newtonsoft.Json",
            "declared": "13.0.1",
            "installed": ["13.0.1"],
        }

        nuget_flat_resp = {
            "versions": ["13.0.1", "13.0.2", "13.0.3"],
        }

        with patch("kevlar.safe_urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(nuget_flat_resp).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_url.return_value = mock_resp

            res = kevlar.check_nuget_package(target)
            self.assertEqual(len(res), 1)
            row = res[0]
            self.assertEqual(row["name"], "Newtonsoft.Json")
            self.assertEqual(row["status"], "patch")
            self.assertEqual(row["latest_same_major"], "13.0.3")
            self.assertEqual(row["latest_absolute"], "13.0.3")

        # Test run_nuget_checker
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "App.csproj"), "w", encoding="utf-8") as f:
                f.write('<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>')

            args = types.SimpleNamespace(path=temp_dir, all=True, concurrent=2, vuls=False)
            with patch("kevlar.safe_urlopen") as mock_url:
                mock_resp = MagicMock()
                mock_resp.read.return_value = json.dumps(nuget_flat_resp).encode("utf-8")
                mock_resp.__enter__.return_value = mock_resp
                mock_url.return_value = mock_resp

                results, _pkg_data, _elapsed = kevlar.run_nuget_checker(args)
                self.assertIsNotNone(results)
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["name"], "Newtonsoft.Json")
        finally:
            shutil.rmtree(temp_dir)

    def test_html_report_template_provider_standalone_and_dev(self):
        """Test HTMLReportTemplateProvider loads from assets in dev mode and falls back to compressed binary in standalone."""
        from unittest.mock import patch

        # Reset cache
        kevlar.HTMLReportTemplateProvider._cached_template = None

        # 1. Dev mode: reads template
        template = kevlar.HTMLReportTemplateProvider.get_template()
        self.assertIsNotNone(template)
        self.assertTrue(template.startswith("<!DOCTYPE html>"))
        self.assertIn("Dependency Status & Security Report", template)

        # 2. Standalone fallback: when asset file does not exist
        kevlar.HTMLReportTemplateProvider._cached_template = None
        with patch("os.path.exists", return_value=False):
            fallback_template = kevlar.HTMLReportTemplateProvider.get_template()
            self.assertIsNotNone(fallback_template)
            self.assertTrue(fallback_template.startswith("<!DOCTYPE html>"))
            self.assertIn("Dependency Status & Security Report", fallback_template)

    def test_go_indirect_and_transitive_remediation_diff(self):
        """Test Go indirect dependency remediation does not generate invalid syntax or broken force override."""
        import tempfile
        import shutil

        temp_dir = tempfile.mkdtemp()
        try:
            go_mod_content = """module myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.0
\tgithub.com/charmbracelet/colorprofile v0.4.1 // indirect
\tgolang.org/x/text v0.37.0 // indirect
)
"""
            go_mod_path = os.path.join(temp_dir, "go.mod")
            with open(go_mod_path, "w", encoding="utf-8") as f:
                f.write(go_mod_content)

            # 1. Test indirect dependency found in go.mod
            results = [{
                "name": "github.com/charmbracelet/colorprofile",
                "declared": "v0.4.1",
                "installed": "v0.4.1",
                "latest": "v0.4.3",
                "latest_same_major": "v0.4.3",
                "latest_absolute": "v0.4.3",
                "status": "patch",
                "vulnerabilities": [],
                "technology": "go",
                "dep_type": "Transitive",
                "project_path": temp_dir,
            }]

            kevlar.populate_remediation_recommendations(results, temp_dir)
            rem = results[0].get("remediation")
            self.assertIsNotNone(rem)
            strategies = rem.get("strategies", [])
            self.assertEqual(len(strategies), 1)
            self.assertEqual(strategies[0]["id"], "direct_upgrade")
            self.assertIn("Update Dependency", strategies[0]["title"])
            self.assertNotIn("Force Transitive Override", [s["id"] for s in strategies])

            # Check that diff replaces the exact line properly
            safe_diff = rem.get("safe")
            self.assertIsNotNone(safe_diff)
            self.assertTrue(any("v0.4.3" in item["html"] for item in safe_diff.get("suggested_code", [])))
            self.assertFalse(any("^" in item["html"] for item in safe_diff.get("suggested_code", [])))

            # 2. Test Go transitive override when not in go.mod
            override_diff = kevlar.generate_override_remediation_diff(
                go_mod_path, "github.com/unknown/transitive", "v1.2.3", "go"
            )
            self.assertIsNotNone(override_diff)
            self.assertTrue(any("replace github.com/unknown/transitive =&gt; github.com/unknown/transitive v1.2.3" in item["html"] for item in override_diff["suggested_code"]))
        finally:
            shutil.rmtree(temp_dir)


    # --------------------------------------------------------------------------
    # MULTI-PROJECT IN-MEMORY CACHE TESTS
    # --------------------------------------------------------------------------
    def test_registry_metadata_and_target_cache(self):
        """Test that identical targets and shared packages across projects use in-memory cache."""
        import json
        from unittest.mock import MagicMock, patch

        target1 = {"name": "react", "declared": "^18.0.0", "installed": ["18.2.0"]}
        target2 = {"name": "react", "declared": "^18.0.0", "installed": ["18.2.0"]}
        target3 = {"name": "react", "declared": "^18.0.0", "installed": ["18.1.0"]}

        npm_payload = {
            "dist-tags": {"latest": "18.3.1"},
            "versions": {
                "18.1.0": {},
                "18.2.0": {},
                "18.3.1": {},
            },
        }

        call_count = 0

        def mock_urlopen(req, timeout=10):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(npm_payload).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        with patch("kevlar.safe_urlopen", side_effect=mock_urlopen):
            # First call: populates both metadata cache and target cache
            res1 = kevlar.check_npm_package(target1)
            self.assertEqual(call_count, 1)
            self.assertEqual(res1[0]["latest"], "18.3.1")
            self.assertEqual(res1[0]["status"], "minor")

            # Second call with identical target: uses target result cache (0 HTTP calls)
            res2 = kevlar.check_npm_package(target2)
            self.assertEqual(call_count, 1)
            self.assertEqual(res2[0]["latest"], "18.3.1")

            # Mutate res2 to verify cache isolation
            res2[0]["status"] = "mutated"
            res2_fresh = kevlar.check_npm_package(target2)
            self.assertEqual(res2_fresh[0]["status"], "minor")

            # Third call with different version: uses metadata cache (0 HTTP calls) and evaluates locally
            res3 = kevlar.check_npm_package(target3)
            self.assertEqual(call_count, 1)
            self.assertEqual(res3[0]["installed"], "18.1.0")
            self.assertEqual(res3[0]["status"], "minor")

    def test_osv_vulnerabilities_cache_reusability(self):
        """Test that OSV vulnerabilities batch querying reuses cached results across projects."""
        import json
        from unittest.mock import MagicMock, patch

        targets_proj1 = [{"name": "lodash", "declared": "4.17.20", "installed": ["4.17.20"]}]
        targets_proj2 = [{"name": "lodash", "declared": "4.17.20", "installed": ["4.17.20"]}]

        batch_payload = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-cached-999",
                            "summary": "Prototype pollution in lodash",
                            "details": "Details...",
                            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                            "database_specific": {"severity": "CRITICAL"},
                        }
                    ]
                }
            ]
        }

        call_count = 0

        def mock_urlopen(req, timeout=15):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(batch_payload).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        with patch("kevlar.safe_urlopen", side_effect=mock_urlopen):
            # First run: queries OSV over network and caches result
            res1 = kevlar.check_osv_vulnerabilities(targets_proj1, "npm", max_workers=2)
            self.assertEqual(call_count, 1)
            self.assertIn(("lodash", "4.17.20"), res1)
            self.assertEqual(res1[("lodash", "4.17.20")][0]["id"], "GHSA-cached-999")

            # Second run (simulating project 2): completely avoids network call
            res2 = kevlar.check_osv_vulnerabilities(targets_proj2, "npm", max_workers=2)
            self.assertEqual(call_count, 1)
            self.assertIn(("lodash", "4.17.20"), res2)
            self.assertEqual(res2[("lodash", "4.17.20")][0]["id"], "GHSA-cached-999")

    def test_clear_kevlar_cache_flushes_all(self):
        """Test that clear_kevlar_cache completely empties all in-memory cache stores."""
        target = {"name": "serde", "declared": "1", "installed": ["1.0.228"]}
        results = [{"name": "serde", "status": "up-to-date"}]

        kevlar._set_cached_target_result("rust", target, results)
        kevlar._set_cached_registry_metadata("rust", "serde", ["1.0.228"])
        kevlar.check_semver_satisfies("1.2.3", ">=1.0.0")

        self.assertIsNotNone(kevlar._get_cached_target_result("rust", target))
        self.assertIsNotNone(kevlar._get_cached_registry_metadata("rust", "serde"))
        self.assertGreaterEqual(kevlar.check_semver_satisfies.cache_info().currsize, 1)

        kevlar.clear_kevlar_cache()

        self.assertIsNone(kevlar._get_cached_target_result("rust", target))
        self.assertIsNone(kevlar._get_cached_registry_metadata("rust", "serde"))
        self.assertEqual(kevlar.check_semver_satisfies.cache_info().currsize, 0)

    def test_ruby_rails_core_gem_remediation(self):
        """Test that SCA remediation for Rails core submodules (e.g. activestorage) targets the rails gem and produces bundle update commands."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            gemfile_content = (
                "source 'https://rubygems.org'\n\n"
                "gem 'rails', '~> 7.2.2'\n"
                "gem 'pg', '~> 1.1'\n"
            )
            gemfile_path = os.path.join(temp_dir, "Gemfile")
            with open(gemfile_path, "w", encoding="utf-8") as f:
                f.write(gemfile_content)

            results = [
                {
                    "name": "rails",
                    "declared": "~> 7.2.2",
                    "installed": ["7.2.2.1"],
                    "status": "minor",
                    "technology": "ruby",
                    "project_path": temp_dir,
                    "dep_type": "Direct",
                    "latest_patch": "7.2.2.2",
                    "latest_same_major": "7.2.3.2",
                    "latest_absolute": "8.0.1",
                    "vulnerabilities": [],
                    "deprecated": False,
                },
                {
                    "name": "activestorage",
                    "declared": "7.2.2.1",
                    "installed": ["7.2.2.1"],
                    "status": "minor",
                    "technology": "ruby",
                    "project_path": temp_dir,
                    "dep_type": "Transitive",
                    "required_by": ["rails"],
                    "latest_patch": "7.2.2.2",
                    "latest_same_major": "7.2.3.2",
                    "latest_absolute": "8.0.1",
                    "vulnerabilities": [{"id": "CVE-2026-9999"}],
                    "deprecated": False,
                },
            ]

            kevlar.populate_remediation_recommendations(results, temp_dir)

            as_rem = results[1].get("remediation")
            self.assertIsNotNone(as_rem)
            strategies = as_rem.get("strategies", [])
            self.assertTrue(any(s["id"] == "rails_upgrade" for s in strategies))

            rails_st = next(s for s in strategies if s["id"] == "rails_upgrade")
            self.assertTrue(rails_st.get("is_recommended"))
            self.assertIn("bundle update rails activestorage", rails_st.get("command", ""))
            self.assertIn("rails test", rails_st.get("validation", ""))
            self.assertIn("version coupling", rails_st.get("diagnostic", ""))

            # Verify safe diff targets rails line in Gemfile and does NOT append activestorage
            safe_diff = as_rem.get("safe")
            self.assertIsNotNone(safe_diff)
            self.assertEqual(safe_diff.get("manifest_path"), gemfile_path)
            self.assertFalse(safe_diff.get("is_addition", False))

            suggested_code_lines = [
                row.get("html", "") for row in safe_diff.get("suggested_code", [])
            ]
            # Must update 'rails', NOT append 'activestorage'
            self.assertTrue(any("rails" in line and "7.2.2.2" in line for line in suggested_code_lines))
            self.assertFalse(any("activestorage" in line for line in suggested_code_lines))

            # Verify minor option targets rails 7.2.3.2
            minor_opt = next(o for o in as_rem.get("options", []) if o.get("id") == "minor")
            minor_suggested_lines = [
                row.get("html", "") for row in minor_opt.get("diff", {}).get("suggested_code", [])
            ]
            self.assertTrue(any("rails" in line and "7.2.3.2" in line for line in minor_suggested_lines))
        finally:
            shutil.rmtree(temp_dir)

    def test_ruby_transitive_non_rails_gem_remediation(self):
        """Test that SCA remediation for non-Rails transitive Ruby dependencies uses lockfile bundle update rather than loose additions."""
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            gemfile_content = (
                "source 'https://rubygems.org'\n\n"
                "gem 'devise', '~> 4.9.0'\n"
            )
            gemfile_path = os.path.join(temp_dir, "Gemfile")
            with open(gemfile_path, "w", encoding="utf-8") as f:
                f.write(gemfile_content)

            results = [
                {
                    "name": "devise",
                    "declared": "~> 4.9.0",
                    "installed": ["4.9.3"],
                    "status": "up-to-date",
                    "technology": "ruby",
                    "project_path": temp_dir,
                    "dep_type": "Direct",
                    "vulnerabilities": [],
                    "deprecated": False,
                },
                {
                    "name": "zeitwerk",
                    "declared": "2.6.0",
                    "installed": ["2.6.0"],
                    "status": "minor",
                    "technology": "ruby",
                    "project_path": temp_dir,
                    "dep_type": "Transitive",
                    "required_by": ["devise"],
                    "latest_patch": None,
                    "latest_same_major": "2.6.18",
                    "latest_absolute": "2.7.0",
                    "vulnerabilities": [{"id": "CVE-2026-1111"}],
                    "deprecated": False,
                },
            ]

            kevlar.populate_remediation_recommendations(results, temp_dir)

            z_rem = results[1].get("remediation")
            self.assertIsNotNone(z_rem)
            strategies = z_rem.get("strategies", [])
            self.assertTrue(any(s["id"] == "bundle_update" for s in strategies))

            lock_st = next(s for s in strategies if s["id"] == "bundle_update")
            self.assertIn("bundle update zeitwerk", lock_st.get("command", ""))
            self.assertIn("transitive", lock_st.get("diagnostic", ""))
        finally:
            shutil.rmtree(temp_dir)

    def test_parse_package_lock_v1_nested_hierarchy(self):
        import json
        import tempfile
        lock_data = {
            "name": "test-v1",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "requires": True,
            "dependencies": {
                "express": {
                    "version": "4.16.4",
                    "integrity": "sha512-j12Uuyb4FMtxewQbVW95EQmuqlzdr638J70gyYoAjqdPHvUUyKaeGQQCKt3bYVI4tuYWxbwlUXlQDthkxV/xEw==",
                    "requires": {
                        "body-parser": "1.18.3"
                    },
                    "dependencies": {
                        "body-parser": {
                            "version": "1.18.3",
                            "integrity": "sha1-WykhmP/dVTs6DyDe0FkrlWlVyLQ=",
                            "requires": {
                                "bytes": "3.0.0",
                                "qs": "6.5.2"
                            },
                            "dependencies": {
                                "bytes": {
                                    "version": "3.0.0",
                                    "integrity": "sha1-0ygVQE1olpn4Wk6k+odV3ROpYEg="
                                },
                                "qs": {
                                    "version": "6.5.2",
                                    "integrity": "sha512-N5ZAX4/LxJmF+7wN74pUD6qAh9/wnvdQcjq9TZjevvXzSUo7bfmw91saq38OW86VMJYIjMpfRTd3UNYoVgWW3g=="
                                }
                            }
                        }
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            json.dump(lock_data, tmp)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity, direct_versions = kevlar.parse_package_lock(tmp_path)
            self.assertEqual(resolved.get("express"), ["4.16.4"])
            self.assertEqual(resolved.get("body-parser"), ["1.18.3"])
            self.assertEqual(resolved.get("bytes"), ["3.0.0"])
            self.assertEqual(resolved.get("qs"), ["6.5.2"])
            self.assertEqual(direct_versions.get("express"), "4.16.4")
            self.assertIn("root", parents.get("express", []))
            self.assertIn("express", parents.get("body-parser", []))
            self.assertIn("body-parser", parents.get("bytes", []))
            self.assertIn("body-parser", parents.get("qs", []))
            self.assertIn("sha512-j12Uuyb4FMtxewQbVW95EQmuqlzdr638J70gyYoAjqdPHvUUyKaeGQQCKt3bYVI4tuYWxbwlUXlQDthkxV/xEw==", integrity.get(("express", "4.16.4"), ""))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_package_lock_v3_workspaces_and_scoped(self):
        import json
        import tempfile
        lock_data = {
            "name": "test-workspaces",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "test-workspaces",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"],
                    "devDependencies": {
                        "typescript": "^5.4.5"
                    }
                },
                "packages/core": {
                    "name": "@workspace-demo/core",
                    "version": "1.0.0",
                    "dependencies": {
                        "lodash": "^4.17.21"
                    }
                },
                "packages/web": {
                    "name": "@workspace-demo/web",
                    "version": "1.0.0",
                    "dependencies": {
                        "@workspace-demo/core": "1.0.0",
                        "axios": "^1.6.8"
                    }
                },
                "node_modules/@types/node": {
                    "version": "20.11.0",
                    "integrity": "sha512-abc"
                },
                "node_modules/axios": {
                    "version": "1.6.8",
                    "integrity": "sha512-def"
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "integrity": "sha512-ghi"
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            json.dump(lock_data, tmp)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity, direct_versions = kevlar.parse_package_lock(tmp_path)
            self.assertEqual(resolved.get("axios"), ["1.6.8"])
            self.assertEqual(resolved.get("lodash"), ["4.17.21"])
            self.assertEqual(resolved.get("@types/node"), ["20.11.0"])
            self.assertIn("root", parents.get("typescript", []))
            self.assertIn("root", parents.get("lodash", []))
            self.assertIn("root", parents.get("@workspace-demo/core", []))
            self.assertIn("root", parents.get("axios", []))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_yarn_lock_classic_multi_specifiers(self):
        import tempfile
        content = (
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT MANUALLY.\n"
            "# yarn lockfile v1\n"
            "\n"
            "\"@babel/core@^7.0.0\", \"@babel/core@^7.12.0\", \"@babel/core@^7.20.0\":\n"
            "  version \"7.24.0\"\n"
            "  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz\"\n"
            "  integrity sha512-5XUvmMuXSDmvQO3STSpuMGWNQSLLOHESJRgK07cPZKNL4wBa82uPwsN4uhJM9GPq8G6hA9TrDrUvo+Vjz1hvw==\n"
            "  dependencies:\n"
            "    \"@babel/parser\" \"^7.24.0\"\n"
            "\n"
            "\"@babel/parser@^7.24.0\":\n"
            "  version \"7.24.0\"\n"
            "  resolved \"https://registry.yarnpkg.com/@babel/parser/-/parser-7.24.0.tgz\"\n"
            "  integrity sha512-QuP/ZKprliGCSpSxP9Y69VoKTM3Z3NAWVW242PzvUMag+WBAUvA3Zb55hQo7cC9ORCR219Wh5TiA83tRKgkYMw==\n"
            "\n"
            "\"debug@2.6.9\", \"debug@^2.2.0\", \"debug@^2.3.3\":\n"
            "  version \"2.6.9\"\n"
            "  resolved \"https://registry.yarnpkg.com/debug/-/debug-2.6.9.tgz\"\n"
            "  integrity sha512-bC7ElrdJaJnPbAP+1EotYvqZsb3ecl5wi6Bfi6BJTUcNowp6cvspg0jXznRTKDjm/E7AdgFBVeAPVMNcKGsHMA==\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity = kevlar.parse_yarn_lock(tmp_path)
            self.assertEqual(resolved.get("@babel/core"), ["7.24.0"])
            self.assertEqual(resolved.get("@babel/parser"), ["7.24.0"])
            self.assertEqual(resolved.get("debug"), ["2.6.9"])
            self.assertIn("@babel/core", parents.get("@babel/parser", []))
            self.assertIn(("@babel/core", "7.24.0"), integrity)
            self.assertIn(("debug", "2.6.9"), integrity)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_yarn_berry_protocols_and_checksum_formats(self):
        import tempfile
        content = (
            "__metadata:\n"
            "  version: 8\n"
            "  cacheKey: 10c0\n"
            "\n"
            "\"clsx@npm:^2.1.0\":\n"
            "  version: 2.1.1\n"
            "  resolution: \"clsx@npm:2.1.1\"\n"
            "  checksum: 10c0/sha512:c607ab9b38030b6ff8d5bfba22e70e3592bc133cf0b809a7b7de283fa71b12b545d65cb5ecad25ef20fa76bf38b584fe3bebb3650228c2eefbd094b8e23b1855\n"
            "\n"
            "\"@org/patched@patch:@org/patched@npm%3A1.0.0#./patch.diff::locator=app%40workspace%3A.\":\n"
            "  version: 1.0.0\n"
            "  resolution: \"@org/patched@patch:@org/patched@npm%3A1.0.0#./patch.diff::locator=app%40workspace%3A.\"\n"
            "  dependencies:\n"
            "    \"is-number\": \"npm:^7.0.0\"\n"
            "  checksum: 8/sha512:47b864a7ef14cf86c8d234771234a75a0b777a88523c14c56e3039d48b67f67747b864a7ef14cf86c8d234771234a75a0b777a88523c14c56e3039d48b67f677\n"
            "\n"
            "\"is-number@npm:^7.0.0\":\n"
            "  version: 7.0.0\n"
            "  resolution: \"is-number@npm:7.0.0\"\n"
            "  checksum: sha1:b32c6955a004ee3fa2691ab1a499ff39e144a1e9\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".lock", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity = kevlar.parse_yarn_lock(tmp_path)
            self.assertEqual(resolved.get("clsx"), ["2.1.1"])
            self.assertEqual(resolved.get("@org/patched"), ["1.0.0"])
            self.assertEqual(resolved.get("is-number"), ["7.0.0"])
            self.assertIn("@org/patched", parents.get("is-number", []))
            
            # Verify clsx checksum converted to sha512- base64
            clsx_integrity = integrity.get(("clsx", "2.1.1"))
            self.assertTrue(clsx_integrity.startswith("sha512-"))
            
            # Verify is-number checksum converted to sha1- base64
            is_num_integrity = integrity.get(("is-number", "7.0.0"))
            self.assertTrue(is_num_integrity.startswith("sha1-"))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_parse_pnpm_lock_monorepo_importers_and_peers(self):
        import tempfile
        content = (
            "lockfileVersion: '9.0'\n"
            "importers:\n"
            "  apps/web:\n"
            "    dependencies:\n"
            "      '@angular/core':\n"
            "        specifier: 17.3.0\n"
            "        version: 17.3.0(zone.js@0.14.4)\n"
            "  packages/ui:\n"
            "    dependencies:\n"
            "      rxjs:\n"
            "        specifier: ^7.8.1\n"
            "        version: 7.8.1\n"
            "packages:\n"
            "  '@angular/core@17.3.0(zone.js@0.14.4)':\n"
            "    resolution: {integrity: sha512-angular_core_hash}\n"
            "    dependencies:\n"
            "      tslib: 2.6.2\n"
            "  rxjs@7.8.1:\n"
            "    resolution: {integrity: sha512-rxjs_hash}\n"
            "    dependencies:\n"
            "      tslib: 2.6.2\n"
            "  tslib@2.6.2:\n"
            "    resolution: {integrity: sha512-tslib_hash}\n"
            "snapshots:\n"
            "  '@angular/core@17.3.0(zone.js@0.14.4)':\n"
            "    dependencies:\n"
            "      tslib: 2.6.2\n"
            "  rxjs@7.8.1:\n"
            "    dependencies:\n"
            "      tslib: 2.6.2\n"
            "  tslib@2.6.2: {}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            resolved, parents, integrity = kevlar.parse_pnpm_lock(tmp_path)
            self.assertEqual(resolved.get("@angular/core"), ["17.3.0"])
            self.assertEqual(resolved.get("rxjs"), ["7.8.1"])
            self.assertEqual(resolved.get("tslib"), ["2.6.2"])
            self.assertIn("@angular/core", parents.get("tslib", []))
            self.assertIn("rxjs", parents.get("tslib", []))
            self.assertIn("root", parents.get("@angular/core", []))
            self.assertIn("root", parents.get("rxjs", []))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @patch("urllib.request.urlopen")
    def test_check_npm_package_scoped_and_registry_metadata(self, mock_urlopen):
        import io
        fake_json = {
            "name": "@nestjs/core",
            "dist-tags": {"latest": "10.3.7"},
            "versions": {
                "9.4.0": {
                    "version": "9.4.0",
                    "dist": {
                        "integrity": "sha512-fakehash940==",
                        "shasum": "0123456789abcdef0123456789abcdef01234567"
                    }
                },
                "10.3.7": {
                    "version": "10.3.7",
                    "dist": {
                        "integrity": "sha512-fakehash1037==",
                        "shasum": "abcdef0123456789abcdef0123456789abcdef01"
                    }
                }
            },
            "repository": {
                "type": "git",
                "url": "git+https://github.com/nestjs/nest.git"
            }
        }
        
        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                import json
                return json.dumps(fake_json).encode("utf-8")

        mock_urlopen.return_value = FakeResponse()
        
        target = {
            "name": "@nestjs/core",
            "declared": "^9.4.0",
            "installed": ["9.4.0"],
            "integrity": {
                "9.4.0": "sha512-fakehash940=="
            }
        }
        
        results = kevlar.check_npm_package(target)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["name"], "@nestjs/core")
        self.assertEqual(res["installed"], "9.4.0")
        self.assertEqual(res["status"], "major")
        self.assertEqual(res["latest_absolute"], "10.3.7")
        self.assertFalse(res["mismatch_checksum"])
        self.assertIn("github.com/nestjs/nest", res["repo_url"])
        self.assertIn("v9.4.0...v10.3.7", res["compare_url"])

    @patch("urllib.request.urlopen")
    def test_check_npm_package_integrity_checksum_mismatch_and_weak(self, mock_urlopen):
        import io
        fake_json = {
            "name": "superagent",
            "dist-tags": {"latest": "8.1.2"},
            "versions": {
                "8.0.9": {
                    "version": "8.0.9",
                    "dist": {
                        "integrity": "sha512-OFFICIAL_INTEGRITY_HASH==",
                        "shasum": "3b25055047b2dfd71c8ee933a39e7cb2811442c7"
                    }
                }
            }
        }
        
        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self):
                import json
                return json.dumps(fake_json).encode("utf-8")

        mock_urlopen.return_value = FakeResponse()

        # Target 1: Mismatched integrity
        target_mismatch = {
            "name": "superagent-mismatch",
            "declared": "^8.0.9",
            "installed": ["8.0.9"],
            "integrity": {
                "8.0.9": "sha512-MALICIOUS_OR_CORRUPTED_HASH=="
            }
        }
        results_mismatch = kevlar.check_npm_package(target_mismatch)
        self.assertTrue(results_mismatch[0]["mismatch_checksum"])

        # Target 2: Matching integrity
        target_match = {
            "name": "superagent-match",
            "declared": "^8.0.9",
            "installed": ["8.0.9"],
            "integrity": {
                "8.0.9": "sha512-OFFICIAL_INTEGRITY_HASH=="
            }
        }
        results_match = kevlar.check_npm_package(target_match)
        self.assertFalse(results_match[0]["mismatch_checksum"])

    def test_check_npm_package_local_and_aliased(self):
        targets = [
            {"name": "local-pkg-workspace", "declared": "workspace:*", "installed": ["workspace:*"]},
            {"name": "local-pkg-portal", "declared": "portal:../my-portal", "installed": ["portal:../my-portal"]},
            {"name": "local-pkg-relative", "declared": "./local-dir", "installed": ["./local-dir"]}
        ]
        for t in targets:
            res = kevlar.check_npm_package(t)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["latest"], "Local")
            self.assertEqual(res[0]["status"], "local")
            self.assertIsNone(res[0]["error"])

    def test_npm_remediation_diff_overrides_and_resolutions(self):
        import tempfile
        
        # Test 1: NPM overrides insertion when overrides does not exist
        npm_pkg_content = (
            "{\n"
            "  \"name\": \"my-app\",\n"
            "  \"version\": \"1.0.0\",\n"
            "  \"dependencies\": {\n"
            "    \"express\": \"^4.18.2\"\n"
            "  }\n"
            "}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            tmp.write(npm_pkg_content)
            tmp_path = tmp.name
        try:
            diff = kevlar.generate_override_remediation_diff(tmp_path, "qs", "6.12.1", "npm")
            self.assertIsNotNone(diff)
            self.assertEqual(diff["manifest_path"], tmp_path)
            suggested = [row["html"] for row in diff["suggested_code"]]
            self.assertTrue(any("overrides" in line for line in suggested))
            self.assertTrue(any("qs" in line and "6.12.1" in line for line in suggested))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        # Test 2: Yarn resolutions insertion
        yarn_pkg_content = (
            "{\n"
            "  \"name\": \"yarn-app\",\n"
            "  \"version\": \"1.0.0\",\n"
            "  \"resolutions\": {\n"
            "    \"lodash\": \"4.17.21\"\n"
            "  }\n"
            "}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            tmp.write(yarn_pkg_content)
            tmp_path = tmp.name
        try:
            diff_yarn = kevlar.generate_override_remediation_diff(tmp_path, "semver", "7.5.2", "yarn")
            self.assertIsNotNone(diff_yarn)
            suggested_yarn = [row["html"] for row in diff_yarn["suggested_code"]]
            self.assertTrue(any("semver" in line and "7.5.2" in line for line in suggested_yarn))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_npm_remediation_diff_addition_direct_and_dev(self):
        import tempfile

        # Case A: Adding to manifest with dependencies
        pkg_json_a = (
            "{\n"
            "  \"name\": \"app-a\",\n"
            "  \"dependencies\": {\n"
            "    \"express\": \"^4.18.2\"\n"
            "  }\n"
            "}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            tmp.write(pkg_json_a)
            tmp_path = tmp.name
        try:
            diff = kevlar.generate_addition_remediation_diff(tmp_path, "helmet", "7.1.0", "npm")
            self.assertIsNotNone(diff)
            self.assertTrue(diff.get("is_addition"))
            suggested = [row["html"] for row in diff["suggested_code"]]
            self.assertTrue(any("helmet" in line and "^7.1.0" in line for line in suggested))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        # Case B: Adding to empty json
        pkg_json_b = "{}\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            tmp.write(pkg_json_b)
            tmp_path = tmp.name
        try:
            diff_empty = kevlar.generate_addition_remediation_diff(tmp_path, "cors", "2.8.5", "npm")
            self.assertIsNotNone(diff_empty)
            suggested_empty = [row["html"] for row in diff_empty["suggested_code"]]
            self.assertTrue(any("dependencies" in line for line in suggested_empty))
            self.assertTrue(any("cors" in line for line in suggested_empty))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_node_engine_nvmrc_and_complex_ranges(self):
        import tempfile
        
        # 1. Test .nvmrc file discovery
        with tempfile.TemporaryDirectory() as tmpdir:
            nvmrc_path = os.path.join(tmpdir, ".nvmrc")
            with open(nvmrc_path, "w", encoding="utf-8") as f:
                f.write("v20.11.0\n")
            
            constraint, source = kevlar.find_node_constraint(tmpdir, None)
            self.assertEqual(constraint, "=v20.11.0")
            self.assertIn(".nvmrc", source)

        # 2. Test .node-version file discovery
        with tempfile.TemporaryDirectory() as tmpdir:
            node_ver_path = os.path.join(tmpdir, ".node-version")
            with open(node_ver_path, "w", encoding="utf-8") as f:
                f.write("22.5.0\n")
            
            constraint, source = kevlar.find_node_constraint(tmpdir, None)
            self.assertEqual(constraint, "=22.5.0")
            self.assertIn(".node-version", source)

        # 3. Test analyze_node_constraint with strictly EOL node constraint
        status_eol, depr_eol, err_eol, rec_eol = kevlar.analyze_node_constraint(">=12.0.0 <14.0.0")
        self.assertEqual(status_eol, "error")
        self.assertIsNotNone(err_eol)
        self.assertIn("only satisfies EOL versions", err_eol)

        # 4. Test analyze_node_constraint with mixed constraint allowing EOL
        status_mix, depr_mix, err_mix, rec_mix = kevlar.analyze_node_constraint(">=12.0.0")
        self.assertEqual(status_mix, "minor")
        self.assertIsNotNone(depr_mix)
        self.assertIn("allows EOL versions", depr_mix)

        # 5. Test analyze_node_constraint with modern active node constraint
        status_ok, depr_ok, err_ok, rec_ok = kevlar.analyze_node_constraint(">=20.0.0")
        self.assertIn(status_ok, ("up-to-date", "minor", "patch"))

    def test_run_npm_checker_on_all_fixtures(self):
        import types
        fixtures = [
            "test/test_npm_v1",
            "test/test_npm_workspaces",
            "test/test_yarn_classic",
            "test/test_yarn_berry",
            "test/test_pnpm_monorepo",
            "test/test_npm_overrides"
        ]
        base_dir = os.path.abspath(os.path.dirname(__file__))
        for rel_path in fixtures:
            fixture_path = os.path.join(base_dir, rel_path)
            if os.path.exists(fixture_path):
                args = types.SimpleNamespace(
                    path=fixture_path,
                    all=True,
                    concurrent=5,
                    vuls=False,
                    suppress=None
                )
                results, pkg_data, elapsed = kevlar.run_npm_checker(args)
                self.assertIsNotNone(results, f"Failed on fixture {rel_path}")
                self.assertTrue(len(results) > 0, f"Expected non-empty results for fixture {rel_path}")

    def test_populate_parent_strategies_multiple_parents(self):
        """Test that transitive dependencies with multiple parents offer upgrade strategies for all upgradable parents."""
        import json
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            pkg_json_path = os.path.join(temp_dir, "package.json")
            pkg_json_content = {
                "name": "multi-parent-test",
                "dependencies": {
                    "parent-a": "1.0.0",
                    "parent-b": "2.0.0",
                },
            }
            with open(pkg_json_path, "w", encoding="utf-8") as f:
                json.dump(pkg_json_content, f, indent=2)

            results = [
                {
                    "name": "parent-a",
                    "declared": "1.0.0",
                    "installed": "1.0.0",
                    "latest_patch": None,
                    "latest_same_major": "1.1.0",
                    "latest_absolute": "2.0.0",
                    "status": "minor",
                    "technology": "npm",
                    "dep_type": "Direct",
                    "project_path": temp_dir,
                },
                {
                    "name": "parent-b",
                    "declared": "2.0.0",
                    "installed": "2.0.0",
                    "latest_patch": None,
                    "latest_same_major": "2.5.0",
                    "latest_absolute": "3.0.0",
                    "status": "minor",
                    "technology": "npm",
                    "dep_type": "Direct",
                    "project_path": temp_dir,
                },
                {
                    "name": "transitive-lib",
                    "declared": None,
                    "installed": "0.9.0",
                    "latest_patch": "0.9.1",
                    "latest_same_major": "0.9.2",
                    "latest_absolute": "1.0.0",
                    "status": "patch",
                    "technology": "npm",
                    "dep_type": "Transitive",
                    "required_by": ["parent-a", "parent-b"],
                    "vulnerabilities": [{"id": "GHSA-test-123"}],
                    "project_path": temp_dir,
                },
            ]

            kevlar.populate_remediation_recommendations(results, temp_dir)

            trans_rem = results[2].get("remediation")
            self.assertIsNotNone(trans_rem)
            strategies = trans_rem.get("strategies", [])
            parent_strategies = [s for s in strategies if s["id"] == "parent_upgrade"]
            self.assertEqual(len(parent_strategies), 1)

            parent_st = parent_strategies[0]
            self.assertIn("Upgrade Parent Packages (2 direct packages)", parent_st["title"])
            self.assertTrue(parent_st.get("is_recommended"))
            self.assertIn("All of them must be updated", parent_st.get("diagnostic", ""))

            # Options check: First option must be Unified Diff
            options = parent_st.get("options", [])
            self.assertTrue(len(options) >= 3)  # unified + step 1 + step 2
            self.assertEqual(options[0]["id"], "unified")
            self.assertIn("Unified Diff: All 2 Parents", options[0]["label"])

            # Verify unified diff has changes for both parents
            unified_diff = options[0].get("diff")
            self.assertIsNotNone(unified_diff)
            suggested_html = " ".join(item["html"] for item in unified_diff.get("suggested_code", []))
            self.assertIn("parent-a", suggested_html)
            self.assertIn("parent-b", suggested_html)

            # Override strategy check
            override_st = next((s for s in strategies if s["id"] == "override"), None)
            self.assertIsNotNone(override_st)
            self.assertFalse(override_st.get("is_recommended"))
        finally:
            shutil.rmtree(temp_dir)

    def test_populate_parent_strategies_multi_file(self):
        """Test that transitive dependencies with parents in different manifest files present multi-file stepper options."""
        import json
        import shutil
        import tempfile

        temp_dir = tempfile.mkdtemp()
        try:
            dir_a = os.path.join(temp_dir, "app-a")
            dir_b = os.path.join(temp_dir, "app-b")
            os.makedirs(dir_a, exist_ok=True)
            os.makedirs(dir_b, exist_ok=True)

            with open(os.path.join(dir_a, "package.json"), "w", encoding="utf-8") as f:
                json.dump({"name": "app-a", "dependencies": {"parent-a": "1.0.0"}}, f, indent=2)

            with open(os.path.join(dir_b, "package.json"), "w", encoding="utf-8") as f:
                json.dump({"name": "app-b", "dependencies": {"parent-b": "2.0.0"}}, f, indent=2)

            results = [
                {
                    "name": "parent-a",
                    "declared": "1.0.0",
                    "installed": "1.0.0",
                    "latest_patch": None,
                    "latest_same_major": "1.1.0",
                    "latest_absolute": "2.0.0",
                    "status": "minor",
                    "technology": "npm",
                    "dep_type": "Direct",
                    "project_path": dir_a,
                },
                {
                    "name": "parent-b",
                    "declared": "2.0.0",
                    "installed": "2.0.0",
                    "latest_patch": None,
                    "latest_same_major": "2.5.0",
                    "latest_absolute": "3.0.0",
                    "status": "minor",
                    "technology": "npm",
                    "dep_type": "Direct",
                    "project_path": dir_b,
                },
                {
                    "name": "transitive-lib",
                    "declared": None,
                    "installed": "0.9.0",
                    "latest_patch": "0.9.1",
                    "latest_same_major": "0.9.2",
                    "latest_absolute": "1.0.0",
                    "status": "patch",
                    "technology": "npm",
                    "dep_type": "Transitive",
                    "required_by": ["parent-a", "parent-b"],
                    "vulnerabilities": [{"id": "GHSA-multi-file"}],
                    "project_path": dir_a,
                },
            ]

            # In this case, parent-a is in dir_a (the project_path of transitive-lib)
            kevlar.populate_remediation_recommendations(results, dir_a)

            trans_rem = results[2].get("remediation")
            self.assertIsNotNone(trans_rem)
            strategies = trans_rem.get("strategies", [])
            parent_strategies = [s for s in strategies if s["id"] == "parent_upgrade"]
            self.assertEqual(len(parent_strategies), 1)
            self.assertIn("Upgrade Parent Package (parent-a)", parent_strategies[0]["title"])
        finally:
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    unittest.main()




