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

if __name__ == "__main__":
    unittest.main()
