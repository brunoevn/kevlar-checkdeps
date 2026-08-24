#!/usr/bin/env python
"""
Dependency Checker Utility
Checks project dependencies for outdated, deprecated, or obsolete versions.
Supports security vulnerability scanning via Google OSV API.
Supports multiple technologies.
"""

import argparse
import base64
import codecs
import ctypes
import functools
import gzip
import json
import os
import random
import re
import string
import sys
import threading
import time
import traceback
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import xml.parsers.expat
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime

import tomllib


# Safe terminal output wrapping to prevent UnicodeEncodeError on Windows
class SafeWriter:
    def __init__(self, original_stream):
        self.original_stream = original_stream
        self.encoding = (
            original_stream.encoding if hasattr(original_stream, "encoding") else None
        ) or "utf-8"

    def write(self, data):
        try:
            self.original_stream.write(data)
        except UnicodeEncodeError:
            self.original_stream.write(
                data.encode(self.encoding, errors="replace").decode(self.encoding)
            )

    def flush(self):
        if hasattr(self.original_stream, "flush"):
            self.original_stream.flush()


sys.stdout = SafeWriter(sys.stdout)
sys.stderr = SafeWriter(sys.stderr)

# Global lock to protect concurrent console writes (sys.stdout, sys.stderr, print)
console_lock = threading.Lock()

from typing import Any, Dict, List, Optional, Set, Tuple, TypedDict, Union


class CheckTarget(TypedDict, total=False):
    name: str
    declared: Optional[str]
    installed: List[str]


class VulnerabilityItem(TypedDict, total=False):
    id: str
    aliases: List[str]
    summary: str
    details: str
    severity: str
    score: Optional[float]
    fixed_version: Optional[str]
    suppressed_reason: Optional[str]


class RemediationOption(TypedDict, total=False):
    id: str
    label: str
    badge: str
    badge_class: str
    diff: Dict[str, Any]


class ScanResultRow(TypedDict, total=False):
    name: str
    declared: Optional[str]
    installed: Optional[str]
    latest: Optional[str]
    latest_same_major: Optional[str]
    latest_absolute: Optional[str]
    status: str
    deprecated: Union[bool, str, None]
    error: Optional[str]
    repo_url: Optional[str]
    compare_url: Optional[str]
    releases_url: Optional[str]
    vulnerabilities: List[VulnerabilityItem]
    remediation: Optional[Dict[str, Any]]


VERSION = "1.10.10"

# External APIs Configuration
URL_NPM_REGISTRY = "https://registry.npmjs.org/"
URL_OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
URL_OSV_VULNS = "https://api.osv.dev/v1/vulns/"
URL_PYPI_REGISTRY = "https://pypi.org/pypi/"
URL_NUGET_REGISTRY = "https://api.nuget.org/v3-flatcontainer/"
URL_PACKAGIST_REGISTRY = "https://repo.packagist.org/p2/"
URL_MAVEN_REGISTRY = "https://repo1.maven.org/maven2/"
URL_GOOGLE_MAVEN = "https://dl.google.com/dl/android/maven2/"
URL_GO_PROXY = "https://proxy.golang.org/"
URL_RUST_REGISTRY = "https://crates.io/api/v1/crates/"
URL_RUBY_REGISTRY = "https://rubygems.org/api/v1/gems/"

# ANSI escape codes for styling (HSL/Curated Theme)
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[38;5;203m"  # Sleek soft red
COLOR_YELLOW = "\033[38;5;221m"  # Soft warm yellow
COLOR_GREEN = "\033[38;5;120m"  # Bright fresh green
COLOR_CYAN = "\033[38;5;86m"  # Pastel cyan
COLOR_MAGENTA = "\033[38;5;213m"  # Bright pinkish/magenta
COLOR_GRAY = "\033[38;5;244m"  # Medium gray

# Default Unicode Icons for visual cues
ICON_OK = "✔"
ICON_INFO = "ℹ"
ICON_WARN = "⚠"
ICON_ERROR = "✖"
ICON_DEPRECATED = "🚫"
ICON_SHIELD = "🛡️"

# Default Unicode Box borders
BORDER_CHARS = {
    "top_left": "┌",
    "horizontal": "─",
    "top_join": "┬",
    "top_right": "┐",
    "mid_left": "├",
    "mid_join": "┼",
    "mid_right": "┤",
    "bot_left": "└",
    "bot_join": "┴",
    "bot_right": "┘",
    "vertical": "│",
}

# Regex for parsing semantic version strings

# Global mapping of supported ecosystems for OSV and manifest files
# The "runner" key is populated at the bottom of the script to prevent NameErrors with checker functions.
TECHNOLOGIES = {
    "npm": {
        "files": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "osv_ecosystem": "npm",
        "runner": None,
    },
    "pip": {
        "files": [
            "requirements.txt",
            "poetry.lock",
            "Pipfile.lock",
            "pdm.lock",
            "pyproject.toml",
        ],
        "osv_ecosystem": "PyPI",
        "runner": None,
    },
    "nuget": {
        "files": [".csproj", ".sln", ".slnx", "packages.config", "project.assets.json"],
        "osv_ecosystem": "NuGet",
        "runner": None,
    },
    "php": {
        "files": ["composer.json", "composer.lock"],
        "osv_ecosystem": "Packagist",
        "runner": None,
    },
    "maven": {"files": ["pom.xml"], "osv_ecosystem": "Maven", "runner": None},
    "go": {"files": ["go.mod"], "osv_ecosystem": "Go", "runner": None},
    "rust": {
        "files": ["Cargo.toml", "Cargo.lock"],
        "osv_ecosystem": "crates.io",
        "runner": None,
    },
    "ruby": {
        "files": ["Gemfile", "Gemfile.lock"],
        "osv_ecosystem": "RubyGems",
        "runner": None,
    },
    "gradle": {
        "files": [
            "build.gradle",
            "build.gradle.kts",
            "gradle.lockfile",
            "libs.versions.toml",
        ],
        "osv_ecosystem": "Maven",
        "runner": None,
    },
    "android": {
        "files": [
            "build.gradle",
            "build.gradle.kts",
            "gradle.lockfile",
            "libs.versions.toml",
        ],
        "osv_ecosystem": "Maven",
        "runner": None,
    },
}

# Cached Regex patterns for performance
RE_SEMVER_ALPHA = re.compile(r"([a-zA-Z]+.*)$")
RE_SEMVER_DIGITS = re.compile(r"\d+")
RE_CLEAN_VER = re.compile(r"^[^\d]*")

# Optimization: Use global compiled regexes to avoid cache lookup and call overhead in hot loops
RE_PEP508_REQ = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s*\[\s*([A-Za-z0-9_,.-]+)\s*\])?\s*(.*)$"
)
RE_PEP508_OP = re.compile(r"([><=^~!]+)\s+")
RE_PEP508_NAME = re.compile(r"^([a-zA-Z0-9\-_\.]+)(.*)$")
RE_PEP508_EXTRA = re.compile(r"^\[[^\]]*\](.*)$")
RE_OPERATOR_PREFIX = re.compile(r"^[~^>=<!\s]+")
RE_OPERATOR_PREFIX_MATCH = re.compile(r"^([~^>=<!\s]+)\s*(.*)$")
RE_OPERATOR_START = re.compile(r"^[~^>=<!]")
RE_NUM_START = re.compile(r"^(\d+)")
RE_DECIMAL_VER = re.compile(r"\d+\.\d+(?:\.\d+)?(?:\.\d+)?")
RE_DECIMAL_VER_STRICT = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:\.\d+)?$")

RE_CVSS4_SEV = re.compile(r"(CVSS:4\.[0-9a-zA-Z/:.]+)")
RE_CVSS3_SEV = re.compile(r"(CVSS:3\.[0-9a-zA-Z/:.]+)")
RE_CVSS2_SEV = re.compile(r"(CVSS:2\.[0-9a-zA-Z/:.]+)")
RE_AV_SEV = re.compile(r"(AV:[NAL]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC])")

SEMVER_REGEX = re.compile(
    r"^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<buildmetadata>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

RE_MARKER_TOKEN = re.compile(
    r"\s*("
    r"\bnot\s+in\b|\bin\b|"
    r"==|!=|<=|>=|<|>|===|~=|"
    r"\band\b|\bor\b|\bnot\b|"
    r"\(|\)|"
    r'"[^"]*"|\'[^\']*\'|'
    r"[a-zA-Z_][a-zA-Z0-9_]*"
    r")\s*"
)
RE_CSPROJ_SLN = re.compile(r'Project\([^)]+\)\s*=\s*"[^"]+"\s*,\s*"([^"]+)"')
RE_MAVEN_PRERELEASE = re.compile(
    r"[-.]?(alpha|beta|rc|cr|m|preview|dev|snapshot|milestone)\d*\b", re.IGNORECASE
)
RE_GRADLE_CONFIG = re.compile(
    r'(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile|compileOnly)\s*\(?\s*[\'"]([^\'":]+):([^\'":]+):([^\'":]+)[\'"]'
)
RE_GRADLE_MAP1 = re.compile(
    r'group\s*:\s*[\'"]([^\'"]+)[\'"]\s*,\s*name\s*:\s*[\'"]([^\'"]+)[\'"]\s*,\s*version\s*:\s*[\'"]([^\'"]+)[\'"]'
)
RE_GRADLE_MAP2 = re.compile(
    r'group\s*=\s*[\'"]([^\'"]+)[\'"]\s*,\s*name\s*=\s*[\'"]([^\'"]+)[\'"]\s*,\s*version\s*=\s*[\'"]([^\'"]+)[\'"]'
)


def init_colors_and_encoding():
    """Enable ANSI escape sequences and adjust icons for stdout encoding compatibility."""
    # 1. Enable virtual terminal processing on Windows for ANSI colors
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            # 0xfffffff5 is STD_OUTPUT_HANDLE
            h_out = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(h_out, mode.value | 0x0004)
        except (AttributeError, OSError, ctypes.ArgumentError):
            pass

    # 2. Check encoding of stdout to fallback if Unicode is not supported
    encoding = getattr(sys.stdout, "encoding", "") or ""
    encoding_str = str(encoding)
    if "utf" not in encoding_str.lower():
        global ICON_OK, ICON_INFO, ICON_WARN, ICON_ERROR, ICON_DEPRECATED, BORDER_CHARS, ICON_SHIELD
        ICON_OK = "[OK]"
        ICON_INFO = "[INFO]"
        ICON_WARN = "[WARN]"
        ICON_ERROR = "[ERROR]"
        ICON_DEPRECATED = "[DEPR]"
        ICON_SHIELD = "[SEC]"

        BORDER_CHARS = {
            "top_left": "+",
            "horizontal": "-",
            "top_join": "+",
            "top_right": "+",
            "mid_left": "+",
            "mid_join": "+",
            "mid_right": "+",
            "bot_left": "+",
            "bot_join": "+",
            "bot_right": "+",
            "vertical": "|",
        }


DEBUG_MODE = False


def _is_safe_path(base_dir, target_path):
    """
    Verifies that target_path resolves within the base_dir directory to prevent Path Traversal.
    """
    if not base_dir or not target_path:
        return False
    real_base = os.path.normcase(os.path.realpath(base_dir))
    real_target = os.path.normcase(os.path.realpath(target_path))
    if real_target == real_base:
        return True
    base_prefix = (
        real_base if real_base.endswith(os.path.sep) else real_base + os.path.sep
    )
    return real_target.startswith(base_prefix)


def _detect_xml_encoding(content):
    """
    Sniffs the encoding of XML bytes based on BOM or the first '<' character alignment.
    Returns the name of the encoding as a string.
    """
    if not content:
        return "utf-8"

    # 1. Check for standard Byte Order Marks (BOM)
    if content.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if content.startswith(b"\xff\xfe\x00\x00"):
        return "utf-32-le"
    if content.startswith(b"\x00\x00\xfe\xff"):
        return "utf-32-be"
    if content.startswith(b"\xff\xfe"):
        return "utf-16"  # Python's utf-16 auto-detects and removes BOM
    if content.startswith(b"\xfe\xff"):
        return "utf-16"  # Python's utf-16 auto-detects and removes BOM

    # 2. Sniff encoding using first occurrence of '<' (0x3c)
    # This detects UTF-16 and UTF-32 without BOM, and handles leading whitespace.
    idx = -1
    for i, b in enumerate(content[:128]):
        if b == 0x3C:
            idx = i
            break

    if idx != -1:
        # Check alignment and surrounding null bytes to determine encoding.
        # UTF-32-BE: '<' is U+0000003C (0x00 0x00 0x00 0x3c), so idx % 4 == 3.
        if idx % 4 == 3 and idx >= 3 and content[idx - 3 : idx] == b"\x00\x00\x00":
            return "utf-32-be"
        # UTF-32-LE: '<' is U+3C000000 (0x3c 0x00 0x00 0x00), so idx % 4 == 0.
        if (
            idx % 4 == 0
            and idx + 3 < len(content)
            and content[idx + 1 : idx + 4] == b"\x00\x00\x00"
        ):
            return "utf-32-le"
        # UTF-16-BE: '<' is U+003C (0x00 0x3c), so idx % 2 == 1.
        if idx % 2 == 1 and idx >= 1 and content[idx - 1] == 0x00:
            return "utf-16-be"
        # UTF-16-LE: '<' is U+3C00 (0x3c 0x00), so idx % 2 == 0.
        if idx % 2 == 0 and idx + 1 < len(content) and content[idx + 1] == 0x00:
            return "utf-16-le"

    return "utf-8"


def calculate_cvss2_score(vector_str):
    """Calculates base CVSS v2 score from a vector string."""
    try:
        parts = {}
        for p in vector_str.split("/"):
            if p.count(":") == 1:
                k, v = p.split(":")
                parts[k] = v

        av = {"L": 0.395, "A": 0.646, "N": 1.0}.get(parts.get("AV"), 1.0)
        ac = {"H": 0.35, "M": 0.61, "L": 0.71}.get(parts.get("AC"), 0.71)
        au = {"M": 0.45, "S": 0.56, "N": 0.704}.get(parts.get("Au"), 0.704)

        c = {"N": 0.0, "P": 0.275, "C": 0.660}.get(parts.get("C"), 0.0)
        i = {"N": 0.0, "P": 0.275, "C": 0.660}.get(parts.get("I"), 0.0)
        a = {"N": 0.0, "P": 0.275, "C": 0.660}.get(parts.get("A"), 0.0)

        impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
        exploitability = 20.0 * av * ac * au

        if impact == 0:
            return 0.0

        score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * 1.176
        return round(score, 1)
    except Exception:
        return None


def calculate_cvss3_score(vector_str):
    """Calculates base CVSS v3.x score from a vector string."""
    try:
        parts = {}
        for p in vector_str.split("/"):
            if p.count(":") == 1:
                k, v = p.split(":")
                parts[k] = v

        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(parts.get("AV"), 0.85)
        ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC"), 0.77)
        ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI"), 0.85)
        scope = parts.get("S", "U")

        if scope == "C":
            pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(parts.get("PR"), 0.85)
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(parts.get("PR"), 0.85)

        c = {"N": 0.0, "L": 0.22, "H": 0.56}.get(parts.get("C"), 0.0)
        i = {"N": 0.0, "L": 0.22, "H": 0.56}.get(parts.get("I"), 0.0)
        a = {"N": 0.0, "L": 0.22, "H": 0.56}.get(parts.get("A"), 0.0)

        iss = 1 - (1 - c) * (1 - i) * (1 - a)

        if scope == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if scope == "C":
            score = 1.08 * (impact + exploitability)
        else:
            score = impact + exploitability

        score_val = min(score, 10.0)
        int_val = int(score_val * 100)
        if int_val % 10 == 0:
            return int_val / 100.0
        else:
            return (int_val - (int_val % 10) + 10) / 100.0

    except Exception:
        return None


def calculate_cvss4_score_approx(vector_str):
    """Approximates base CVSS v4.0 score by translating metrics to v3 equivalent."""
    try:
        parts = {}
        for p in vector_str.split("/"):
            if p.count(":") == 1:
                k, v = p.split(":")
                parts[k] = v

        av = parts.get("AV", "N")
        ac = parts.get("AC", "L")
        if parts.get("AT") == "P":
            ac = "H"
        pr = parts.get("PR", "N")
        ui = "N"
        if parts.get("UI") in {"A", "R"}:
            ui = "R"

        scope = "U"
        if (
            parts.get("SC") in {"H", "L"}
            or parts.get("SI") in {"H", "L"}
            or parts.get("SA") in {"H", "L"}
        ):
            scope = "C"

        c = parts.get("VC", "N")
        i = parts.get("VI", "N")
        a = parts.get("VA", "N")

        v3_vector = (
            f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
        )
        return calculate_cvss3_score(v3_vector)
    except Exception:
        return None


def get_severity_level(vuln):
    """Determines the severity level (malicious, critical, high, medium, low, unknown) of a vulnerability."""
    # FIXED: Unified severity heuristics globally
    if not vuln:
        return "unknown"
    vuln_id = ""
    if isinstance(vuln, dict):
        vuln_id = vuln.get("id", "")
        if vuln_id and vuln_id.startswith("MAL-"):
            return "malicious"
        severity = vuln.get("severity", "UNKNOWN")
    else:
        severity = str(vuln)

    sev_upper = severity.upper()

    # 1. Exact matches or plain text checks first
    if "CRITICAL" in sev_upper:
        return "critical"
    if "HIGH" in sev_upper or "UNSOUND" in sev_upper:
        return "high"
    if (
        "MEDIUM" in sev_upper
        or "MODERATE" in sev_upper
        or "UNMAINTAINED" in sev_upper
        or "WARNING" in sev_upper
        or "NOTICE" in sev_upper
        or "INFORMATIONAL" in sev_upper
    ):
        return "medium"
    if "LOW" in sev_upper:
        return "low"
    if "MALICIOUS" in sev_upper:
        return "malicious"

    # 2. CVSS score calculations
    if "CVSS" in sev_upper or "AV:" in sev_upper:
        m4 = RE_CVSS4_SEV.search(sev_upper)
        if m4:
            vector = m4.group(1)
            score = calculate_cvss4_score_approx(vector)
            if score is not None:
                if score >= 9.0:
                    return "critical"
                elif score >= 7.0:
                    return "high"
                elif score >= 4.0:
                    return "medium"
                elif score >= 0.1:
                    return "low"

        m3 = RE_CVSS3_SEV.search(sev_upper)
        if m3:
            vector = m3.group(1)
            score = calculate_cvss3_score(vector)
            if score is not None:
                if score >= 9.0:
                    return "critical"
                elif score >= 7.0:
                    return "high"
                elif score >= 4.0:
                    return "medium"
                elif score >= 0.1:
                    return "low"

        vector2 = None
        m2 = RE_CVSS2_SEV.search(sev_upper)
        if m2:
            vector2 = m2.group(1)
        elif "AV:" in sev_upper:
            m_raw2 = RE_AV_SEV.search(sev_upper)
            if m_raw2:
                vector2 = m_raw2.group(1)

        if vector2:
            score = calculate_cvss2_score(vector2)
            if score is not None:
                if score >= 9.0:
                    return "critical"
                elif score >= 7.0:
                    return "high"
                elif score >= 4.0:
                    return "medium"
                elif score >= 0.1:
                    return "low"

    # 3. Fallback metric-based heuristic (similar to normalize_severity_to_text)
    s = severity.lower()
    import re as _re

    def _metric(vector, key):
        m = _re.search(r"/" + key.lower() + r"(?=[:/])([nhml])", vector)
        if not m:
            m = _re.search(r"(?:^|/)" + key.lower() + r":([nhml])", vector)
        return m.group(1) if m else "n"

    if "cvss:3" in s or "cvss:2" in s or "av:" in s:
        c = _metric(s, "C")
        i = _metric(s, "I")
        a = _metric(s, "A")
        sc = _metric(s, "S")
        if sc == "c" and (c == "h" or i == "h"):
            return "critical"
        if c == "h" or i == "h" or a == "h":
            return "high"
        if c == "l" or i == "l" or a == "l":
            return "medium"
        return "low"

    if "cvss:4" in s:
        vc = _metric(s, "VC")
        vi = _metric(s, "VI")
        va = _metric(s, "VA")
        if vc == "h" and vi == "h":
            return "critical"
        if vc == "h" or vi == "h" or va == "h":
            return "high"
        if vc == "l" or vi == "l" or va == "l":
            return "medium"
        return "low"

    return "unknown"


class SecureXMLBuilder:
    def __init__(self, max_depth=15, max_expanded_size=10 * 1024 * 1024):
        self.max_depth = max_depth
        self.max_expanded_size = max_expanded_size
        self.depth = 0
        self.total_size = 0
        self.stack = []
        self.root = None

    def start_element(self, name, attrs):
        self.depth += 1
        if self.depth > self.max_depth:
            raise ValueError(
                f"XML parsing rejected: Node depth exceeds limit of {self.max_depth}"
            )

        if "}" in name and not name.startswith("{"):
            name = "{" + name

        processed_attrs = {}
        for k, v in attrs.items():
            if "}" in k and not k.startswith("{"):
                k = "{" + k
            processed_attrs[k] = v

        self.total_size += len(name)
        for k, v in processed_attrs.items():
            self.total_size += len(k) + len(v)

        if self.total_size > self.max_expanded_size:
            raise ValueError("XML parsing rejected: Expanded data size limit exceeded")

        element = ET.Element(name, processed_attrs)
        if not self.stack:
            self.root = element
        else:
            self.stack[-1].append(element)
        self.stack.append(element)

    def end_element(self, name):
        self.depth -= 1
        if "}" in name and not name.startswith("{"):
            name = "{" + name
        if self.stack:
            self.stack.pop()

    def char_data(self, data):
        self.total_size += len(data)
        if self.total_size > self.max_expanded_size:
            raise ValueError("XML parsing rejected: Expanded data size limit exceeded")
        if self.stack:
            elem = self.stack[-1]
            if len(elem) == 0:
                elem.text = (elem.text or "") + data
            else:
                last_child = elem[-1]
                last_child.tail = (last_child.tail or "") + data


def parse_secure_xml(content, max_depth=15, max_expanded_size=10 * 1024 * 1024):
    builder = SecureXMLBuilder(max_depth, max_expanded_size)

    encoding = "utf-8"
    if isinstance(content, bytes):
        encoding = _detect_xml_encoding(content)
        try:
            prefix = content[:1024].decode("latin-1", errors="ignore")
            m = re.search(
                r'<\?xml\s+[^>]*encoding\s*=\s*["\']([^"\']+)["\']',
                prefix,
                re.IGNORECASE,
            )
            if m:
                encoding = m.group(1)
        except (UnicodeError, IndexError, AttributeError):
            pass
        try:
            content_str = content.decode(encoding, errors="replace")
        except Exception:
            content_str = content.decode("latin-1", errors="replace")
            encoding = "latin-1"
    else:
        content_str = content
        m = re.search(
            r'<\?xml\s+[^>]*encoding\s*=\s*["\']([^"\']+)["\']',
            content_str[:1024],
            re.IGNORECASE,
        )
        if m:
            encoding = m.group(1)

    # FIXED: Re-encode string back to the detected/declared encoding and pass it to ParserCreate
    try:
        content_bytes = content_str.encode(encoding, errors="replace")
    except Exception:
        content_bytes = content_str.encode("utf-8", errors="replace")
        encoding = "utf-8"

    parser = xml.parsers.expat.ParserCreate(encoding=encoding, namespace_separator="}")
    parser.StartElementHandler = builder.start_element
    parser.EndElementHandler = builder.end_element
    parser.CharacterDataHandler = builder.char_data

    # 1 y 2. Delegar la validación a los handlers de Expat y lanzar ValueError inmediato
    def forbid_doctype(*args, **kwargs):
        raise ValueError(
            "XML parsing rejected: XML contains forbidden DOCTYPE declarations."
        )

    def forbid_entity(*args, **kwargs):
        raise ValueError(
            "XML parsing rejected: XML contains forbidden Entity declarations."
        )

    parser.StartDoctypeDeclHandler = forbid_doctype
    parser.EntityDeclHandler = forbid_entity

    try:
        parser.Parse(content_bytes, True)
    except xml.parsers.expat.ExpatError as e:
        err = ET.ParseError(str(e))
        err.code = e.code
        err.offset = e.offset
        err.position = (e.lineno, e.offset)
        raise err
    return builder.root


def safe_et_parse(source):
    """
    Safely parses an XML file path using ET, validating it first.
    Returns an ElementTree-like object.
    """
    with open(source, "rb") as f:
        content = f.read()
    root = parse_secure_xml(content)
    return ET.ElementTree(root)


def safe_et_fromstring(text):
    """
    Safely parses an XML string or bytes using ET, validating it first.
    Returns the root Element.
    """
    return parse_secure_xml(text)


def _sanitize_error_message(exc, target_name):
    """
    Translates an internal exception into a business-safe, standardized error message
    without exposing system-level details, internal URLs, paths, or tracebacks.
    """
    msg = str(exc)

    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 404:
            return "Registry returned not found (404)"
        elif exc.code in {408, 504}:
            return "Registry communication timeout"
        elif exc.code >= 500:
            return "Internal server error on registry side"
        else:
            return f"Registry returned unexpected HTTP status {exc.code}"

    if isinstance(exc, urllib.error.URLError):
        reason_str = str(exc.reason).lower()
        if "timeout" in reason_str or "timed out" in reason_str:
            return "Registry communication timeout"
        elif "ssl" in reason_str or "cert" in reason_str:
            return "Registry SSL handshake failed"
        else:
            return "Registry connection failed or address unresolved"

    if isinstance(exc, json.JSONDecodeError):
        return "Malformed registry response format"

    if isinstance(exc, ET.ParseError):
        return "Malformed manifest format"

    if isinstance(exc, ValueError):
        if "XML parsing rejected" in msg or "DOCTYPE" in msg or "ENTITY" in msg:
            return "Malformed manifest format"
        return "Invalid configuration or manifest parameters"

    exc_type_lower = type(exc).__name__.lower()
    if "timeout" in exc_type_lower or "timedout" in exc_type_lower:
        return "Registry communication timeout"

    return "Unexpected execution error during analysis"


def safe_urlopen(req, timeout=10, max_retries=5, backoff=0.5):
    """Safely opens a URL with retries, exponential backoff, Retry-After handling, and default headers."""
    # 1. Extraer la URL de forma segura
    if isinstance(req, str):
        url_str = req
    elif isinstance(req, urllib.request.Request) or hasattr(req, "full_url"):
        url_str = req.full_url
    elif hasattr(req, "get_full_url"):
        url_str = req.get_full_url()
    else:
        raise ValueError("Protocolo de comunicación no permitido")

    # 2. Sanitizar de forma estricta la URL entrante
    url_str = url_str.strip()
    if any(c in url_str for c in "\r\n\t \x00"):
        raise ValueError("Protocolo de comunicación no permitido")

    # 3. Validar esquema usando urlparse (solo permitir https y http, priorizando https)
    parsed = urllib.parse.urlparse(url_str)
    scheme = parsed.scheme.lower()
    if scheme not in {"https", "http"}:
        raise ValueError("Protocolo de comunicación no permitido")

    # 4. Asegurar que la validación ocurre antes de procesar/instanciar el Request hacia la red
    if isinstance(req, str):
        req = urllib.request.Request(url_str)
    else:
        req.full_url = url_str

    if not req.has_header("User-Agent"):
        req.add_header("User-Agent", f"Kevlar-CheckDeps/{VERSION}")

    last_err = None
    for attempt in range(max_retries):
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            if e.code == 429:
                last_err = e
                if attempt < max_retries - 1:
                    retry_after = (
                        e.headers.get("Retry-After")
                        if hasattr(e, "headers") and e.headers
                        else None
                    )
                    wait_sec = None
                    if retry_after:
                        try:
                            wait_sec = float(retry_after)
                        except ValueError:
                            pass
                    if wait_sec is None:
                        wait_sec = backoff * (2**attempt) + random.uniform(0.5, 1.5)
                    time.sleep(wait_sec)
                    continue
                raise
            if e.code < 500:
                raise
            last_err = e
        except (
            urllib.error.URLError,
            ConnectionResetError,
            TimeoutError,
            OSError,
        ) as e:
            last_err = e

        if attempt < max_retries - 1:
            time.sleep(backoff * (2**attempt) + random.uniform(0.1, 0.5))

    if last_err:
        raise last_err


class PrereleaseKey:
    def __init__(self, prerelease):
        self.prerelease = prerelease or ""

    def __lt__(self, other):
        return compare_prereleases(self.prerelease, other.prerelease) < 0

    def __eq__(self, other):
        return compare_prereleases(self.prerelease, other.prerelease) == 0


def _split_mixed_identifier(s):
    """Splits a mixed alphanumeric identifier into chunks of digit and non-digit sequences.
    Digits are converted to integers, non-digits remain as strings.
    """
    chunks = []
    current = []
    is_digit = None
    for char in s:
        char_is_digit = char.isdigit()
        if is_digit is None:
            is_digit = char_is_digit
            current.append(char)
        elif char_is_digit == is_digit:
            current.append(char)
        else:
            chunk_str = "".join(current)
            if is_digit:
                chunks.append(int(chunk_str))
            else:
                chunks.append(chunk_str)
            is_digit = char_is_digit
            current = [char]
    if current:
        chunk_str = "".join(current)
        if is_digit:
            chunks.append(int(chunk_str))
        else:
            chunks.append(chunk_str)
    return chunks


def _compare_mixed_identifiers(part1, part2):
    """Compares two non-numeric identifiers chunk by chunk.
    Numeric chunks are compared numerically.
    Alphanumeric chunks are compared lexicographically.
    Numeric chunks have lower precedence than alphanumeric chunks.
    """
    chunks1 = _split_mixed_identifier(part1)
    chunks2 = _split_mixed_identifier(part2)

    for c1, c2 in zip(chunks1, chunks2):
        type1 = type(c1)
        type2 = type(c2)

        if type1 is type2:
            if c1 < c2:
                return -1
            elif c1 > c2:
                return 1
        else:
            # Numeric chunk (int) vs alphanumeric chunk (str).
            # Numeric chunks have lower precedence.
            if type1 is int:
                return -1
            else:
                return 1

    if len(chunks1) < len(chunks2):
        return -1
    elif len(chunks1) > len(chunks2):
        return 1

    # Tie-breaker fallback to standard lexicographical comparison (e.g. comparing "rc01" vs "rc1")
    if part1 < part2:
        return -1
    elif part1 > part2:
        return 1
    return 0


def compare_prereleases(p1, p2):
    """Compares two pre-release strings according to SemVer rules.
    Empty string (stable release) has higher precedence than any pre-release.
    Numeric identifiers are compared numerically.
    Alphanumeric identifiers are compared lexicographically.
    Numeric identifiers have lower precedence than non-numeric identifiers.
    """
    if p1 == p2:
        return 0
    if not p1:  # stable is higher
        return 1
    if not p2:  # stable is higher
        return -1

    parts1 = p1.split(".")
    parts2 = p2.split(".")

    for part1, part2 in zip(parts1, parts2):
        is_num1 = part1.isdigit()
        is_num2 = part2.isdigit()

        if is_num1 and is_num2:
            n1 = int(part1)
            n2 = int(part2)
            if n1 < n2:
                return -1
            elif n1 > n2:
                return 1
        elif not is_num1 and not is_num2:
            res = _compare_mixed_identifiers(part1, part2)
            if res != 0:
                return res
        else:
            return -1 if is_num1 else 1

    if len(parts1) < len(parts2):
        return -1
    elif len(parts1) > len(parts2):
        return 1
    return 0


# ⚡ Bolt: Cache semantic version parsing to optimize hot loops during lockfile evaluations.
# Impact: Reduces parse_semver execution time by ~90% for repeated lookups.
@functools.lru_cache(maxsize=2048)
def parse_semver(version_str):
    """Parses a version string into (epoch, major, minor, patch, revision, prerelease)."""
    if not version_str:
        return (0, 0, 0, 0, 0, "")

    clean_str = version_str.strip()
    if clean_str.lower().startswith("v"):
        clean_str = clean_str[1:]

    if "+" in clean_str:
        clean_str = clean_str.split("+", 1)[0]

    epoch = 0
    if "!" in clean_str:
        parts = clean_str.split("!", 1)
        try:
            epoch = int(parts[0])
        except ValueError:
            epoch = 0
        clean_str = parts[1]

    prerelease = ""
    if "-" in clean_str:
        clean_str, prerelease = clean_str.split("-", 1)
    else:
        m = RE_SEMVER_ALPHA.search(clean_str)
        if m:
            qualifier = m.group(1).lower()
            if any(
                q in qualifier
                for q in ("a", "b", "rc", "cr", "dev", "alpha", "beta", "preview")
            ):
                start_idx = m.start()
                prerelease = clean_str[start_idx:]
                clean_str = clean_str[:start_idx]
                clean_str = clean_str.removesuffix(".")

    if prerelease:
        p_lower = prerelease.lower()
        if not any(
            q in p_lower
            for q in (
                "a",
                "b",
                "rc",
                "cr",
                "dev",
                "alpha",
                "beta",
                "preview",
                "snapshot",
                "milestone",
                "pre",
            )
        ):
            prerelease = ""

    digits = RE_SEMVER_DIGITS.findall(clean_str)
    major = 0
    minor = 0
    patch = 0
    revision = 0

    if len(digits) >= 4:
        major = int(digits[0])
        minor = int(digits[1])
        patch = int(digits[2])
        revision = int(digits[3])
    elif len(digits) == 3:
        major = int(digits[0])
        minor = int(digits[1])
        patch = int(digits[2])
    elif len(digits) == 2:
        major = int(digits[0])
        minor = int(digits[1])
    elif len(digits) == 1:
        major = int(digits[0])

    return (epoch, major, minor, patch, revision, prerelease)


def compare_versions(v1_str, v2_str):
    """Compares two semver version strings.
    Returns:
       -1 if v1 < v2
        0 if v1 == v2
        1 if v1 > v2
    """
    t1 = parse_semver(v1_str)
    t2 = parse_semver(v2_str)

    if t1[:5] < t2[:5]:
        return -1
    elif t1[:5] > t2[:5]:
        return 1

    return compare_prereleases(t1[5], t2[5])


def fetch_node_schedule():
    """Fetches the official Node.js release schedule from GitHub.
    Returns:
        dict: A dictionary mapping major versions to dicts with EOL and maintenance dates.
    """
    url = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"

    schedule = {}
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (Kevlar Dependency Scanner)"}
        )
        with safe_urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            for k, v in data.items():
                major = k.removeprefix("v")
                schedule[major] = {
                    "maintenance": v.get("maintenance", "N/A"),
                    "end": v.get("end", "N/A"),
                }
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning fetching Node.js release schedule: {e}{COLOR_RESET}"
        )

    return schedule


def satisfy_term(version_str, term):
    try:
        term = term.strip()
        if not term or term in {"*", "x"}:
            return True

        op = ""
        for possible_op in (">=", "<=", ">", "<", "^", "~", "=="):
            if term.startswith(possible_op):
                op = possible_op
                break
        if not op and term.startswith("="):
            op = "="

        ver_part = term[len(op) :] if op else term

        _, v_maj, v_min, v_pat, _, _ = parse_semver(version_str)

        if (ver_part.endswith((".x", ".*"))) and op not in {
            "^",
            "~",
        }:
            parts = ver_part.split(".")
            try:
                if len(parts) == 2:
                    return v_maj == int(parts[0])
                elif len(parts) == 3:
                    return v_maj == int(parts[0]) and v_min == int(parts[1])
            except ValueError:
                return False
            return True

        if not op:
            parts = ver_part.split(".")
            if len(parts) == 1:
                try:
                    return v_maj == int(parts[0])
                except ValueError:
                    pass
            elif len(parts) == 2:
                try:
                    return v_maj == int(parts[0]) and v_min == int(parts[1])
                except ValueError:
                    pass

        _, t_maj, t_min, t_pat, _, _ = parse_semver(ver_part)

        if op == ">=":
            return compare_versions(version_str, ver_part) >= 0
        elif op == "<=":
            return compare_versions(version_str, ver_part) <= 0
        elif op == ">":
            return compare_versions(version_str, ver_part) > 0
        elif op == "<":
            return compare_versions(version_str, ver_part) < 0
        elif op in {"=", "==", ""}:
            return compare_versions(version_str, ver_part) == 0
        elif op == "^":
            if compare_versions(version_str, ver_part) < 0:
                return False
            if t_maj > 0:
                return v_maj == t_maj

            # Zero series caret evaluation
            clean_ver = ver_part.strip().lower()
            clean_ver = clean_ver.removeprefix("v")
            if "+" in clean_ver:
                clean_ver = clean_ver.split("+", 1)[0]
            if "-" in clean_ver:
                clean_ver = clean_ver.split("-", 1)[0]

            parts = [p.strip() for p in clean_ver.split(".") if p.strip()]

            is_wildcard_minor = len(parts) >= 2 and parts[1] in {"x", "*"}
            is_only_major_zero = len(parts) == 1 and parts[0] == "0"
            if is_only_major_zero or is_wildcard_minor:
                return v_maj == 0

            is_wildcard_patch = (
                len(parts) >= 3
                and parts[0] == "0"
                and parts[1] == "0"
                and parts[2] in {"x", "*"}
            )
            if is_wildcard_patch:
                return v_maj == 0 and v_min == 0 and v_pat == t_pat

            if t_min > 0:
                return v_maj == 0 and v_min == t_min

            return v_maj == 0 and v_min == 0 and v_pat == t_pat

        elif op == "~":
            if compare_versions(version_str, ver_part) < 0:
                return False

            clean_ver = ver_part.strip().lower()
            clean_ver = clean_ver.removeprefix("v")
            if "+" in clean_ver:
                clean_ver = clean_ver.split("+", 1)[0]
            if "-" in clean_ver:
                clean_ver = clean_ver.split("-", 1)[0]

            parts = [
                p.strip()
                for p in clean_ver.split(".")
                if p.strip() and p.strip() not in {"x", "*"}
            ]
            parts_count = len(parts)

            if parts_count >= 2:
                return v_maj == t_maj and v_min == t_min
            else:
                return v_maj == t_maj
    except Exception:
        return True
    return True


def check_semver_satisfies(version_str, range_str):
    """Checks if version_str satisfies range_str according to semver rules."""
    if not range_str or range_str.strip() in {"*", "x", "any"}:
        return True

    range_str = re.sub(r"([><=^~])\s+", r"\1", range_str.strip())
    or_parts = range_str.split("||")

    for or_part in or_parts:
        or_part = or_part.strip()
        if not or_part:
            continue

        # Treat commas as logical AND delimiters by replacing them with spaces
        and_terms = or_part.replace(",", " ").split()
        part_satisfied = True

        for term in and_terms:
            if not satisfy_term(version_str, term):
                part_satisfied = False
                break

        if part_satisfied:
            return True

    return False


def _check_all_targets_unified(targets, check_func, label, max_workers):
    """Unified parallel check runner with try/except wrappers and progress reporting."""
    results = []
    completed = 0
    total = len(targets)

    if not targets:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_func, t): t for t in targets}
        for future in as_completed(futures):
            completed += 1
            with console_lock:
                sys.stdout.write(f"\r{label}: {completed}/{total}... ")
                sys.stdout.flush()
            try:
                res = future.result()
                if isinstance(res, list):
                    results.extend(res)
                elif res:
                    results.append(res)
            except Exception as e:
                target_pkg = futures[future]
                name = target_pkg.get("name", "unknown")
                sanitized_msg = _sanitize_error_message(e, name)

                with console_lock:
                    if DEBUG_MODE:
                        print(
                            f"\n{COLOR_RED}{ICON_ERROR} Error checking {name}: {e}{COLOR_RESET}"
                        )
                        traceback.print_exc(file=sys.stdout)
                    else:
                        print(
                            f"\n{COLOR_RED}{ICON_ERROR} Error checking {name}: {sanitized_msg}{COLOR_RESET}"
                        )

                installed = target_pkg.get("installed", [])
                versions_to_check = (
                    installed if installed else [target_pkg.get("declared")]
                )
                for ver_str in versions_to_check:
                    results.append(
                        {
                            "name": name,
                            "declared": ver_str,
                            "installed": ver_str,
                            "latest": "unknown",
                            "status": "error",
                            "deprecated": False,
                            "error": sanitized_msg,
                        }
                    )

    with console_lock:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
    return results


def _is_major_version_eol(major_version: str, schedule: dict, today_date: date) -> bool:
    """Determines if a specific major version of Node.js is End-of-Life (EOL)."""
    end_info = schedule.get(major_version)
    if not end_info:
        # Placeholder or unknown future versions are not EOL
        return False
    end_str = end_info.get("end")
    if not end_str:
        return True
    try:
        end_date = datetime.strptime(end_str, "%Y-%m-%d").date()
        return end_date <= today_date
    except Exception:
        return True


def analyze_node_constraint(constraint_str):
    """Analyzes a Node.js version constraint and checks if it permits EOL versions.
    Returns (status, deprecated_msg, error_msg, latest_recommendation).
    """
    FUTURE_MAJOR_PLACEHOLDER = "99"
    DEFAULT_FALLBACK_MAJOR = "22"

    schedule = fetch_node_schedule()
    if not schedule:
        return (
            "error",
            None,
            "We cannot recommend a valid version at this time as there is no internet connection.",
            "unknown",
        )

    today = date.today()

    # Sort and filter known major versions from the schedule keys
    test_majors = sorted([k for k in schedule if k.isdigit()], key=int)
    test_majors.append(FUTURE_MAJOR_PLACEHOLDER)

    # Filter for active (non-EOL) even major versions
    active_even_majors = [
        major
        for major in test_majors
        if major != FUTURE_MAJOR_PLACEHOLDER
        and int(major) % 2 == 0
        and not _is_major_version_eol(major, schedule, today)
    ]
    latest_lts = (
        active_even_majors[-1] if active_even_majors else DEFAULT_FALLBACK_MAJOR
    )

    if not constraint_str or constraint_str.strip() in {"*", "x", "any"}:
        return (
            "minor",
            f"Node.js engine constraint is wildcard or missing. Recommend specifying >={latest_lts}.0.0.",
            None,
            f">={latest_lts}.0.0",
        )

    # Find all major versions satisfied by the constraint
    satisfied_majors = [
        major
        for major in test_majors
        if check_semver_satisfies(f"{major}.0.0", constraint_str)
    ]

    # Categorize satisfied major versions into EOL and supported
    eol_majors = [
        major
        for major in satisfied_majors
        if _is_major_version_eol(major, schedule, today)
    ]
    supported_majors = [
        major
        for major in satisfied_majors
        if not _is_major_version_eol(major, schedule, today)
    ]

    # Map active even majors as integers
    supported_even_majors = [int(major) for major in active_even_majors]

    recommendations = []
    if eol_majors:
        highest_eol = max(int(m) for m in eol_majors)

        # Previous active supported
        prev_opts = [m for m in supported_even_majors if m < highest_eol]
        if prev_opts:
            recommendations.append(f">={max(prev_opts)}.0.0")

        # Next active supported
        next_opts = [m for m in supported_even_majors if m > highest_eol]
        if next_opts:
            recommendations.append(f">={min(next_opts)}.0.0")

        # Fallback if none found
        if not recommendations and supported_even_majors:
            recommendations.append(f">={max(supported_even_majors)}.0.0")
    else:
        # Wildcard / missing constraint fallback
        if len(supported_even_majors) >= 2:
            recommendations.append(f">={supported_even_majors[-2]}.0.0")
            recommendations.append(f">={supported_even_majors[-1]}.0.0")
        elif supported_even_majors:
            recommendations.append(f">={supported_even_majors[-1]}.0.0")

    if len(recommendations) > 1:
        recommendation = " or ".join(recommendations)
    elif recommendations:
        recommendation = recommendations[0]
    else:
        recommendation = f">={DEFAULT_FALLBACK_MAJOR}.0.0"

    recs_detail = []
    for rec in recommendations:
        m_num = rec.replace(">=", "").split(".")[0]
        m_info = schedule.get(m_num, {})
        m_date = m_info.get("maintenance", "N/A")
        end_date = m_info.get("end", "N/A")
        recs_detail.append(f"v{m_num} (Maintenance: {m_date}, EOL: {end_date})")

    detail_str = ""
    if recs_detail:
        detail_str = "\n    * " + "\n    * ".join(recs_detail)

    if eol_majors and not supported_majors:
        status = "error"
        msg = f"Node.js constraint '{constraint_str}' only satisfies EOL versions ({', '.join(eol_majors)}). Recommend updating constraint to {recommendation}.{detail_str}"
        return status, None, msg, recommendation
    elif eol_majors and supported_majors:
        status = "minor"
        msg = f"Node.js constraint '{constraint_str}' allows EOL versions ({', '.join(eol_majors)}). Recommend updating lower bound to {recommendation}.{detail_str}"
        return status, msg, None, recommendation
    else:
        latest_stable = (
            f"v{supported_even_majors[-1]}"
            if supported_even_majors
            else f"v{DEFAULT_FALLBACK_MAJOR}"
        )
        return "up-to-date", None, None, latest_stable


def find_node_constraint(base_path, pkg_data):
    """Finds Node.js version constraint from package.json, .nvmrc, or .node-version."""
    if pkg_data and "engines" in pkg_data and isinstance(pkg_data["engines"], dict):
        node_req = pkg_data["engines"].get("node")
        if node_req:
            return node_req, "package.json (engines.node)"

    nvmrc_path = os.path.join(base_path, ".nvmrc")
    if os.path.exists(nvmrc_path):
        try:
            with open(nvmrc_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    content = content.split("#")[0].strip()
                    if content and not content.startswith("lts"):
                        if re.match(r"^v?\d+", content):
                            return f"={content}", ".nvmrc"
                        return content, ".nvmrc"
        except OSError:
            pass

    node_ver_path = os.path.join(base_path, ".node-version")
    if os.path.exists(node_ver_path):
        try:
            with open(node_ver_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    content = content.split("#")[0].strip()
                    if content:
                        if re.match(r"^v?\d+", content):
                            return f"={content}", ".node-version"
                        return content, ".node-version"
        except OSError:
            pass

    return None, None


def classify_update(installed_str, latest_str):
    """Classifies the update difference between installed and latest version."""
    if not installed_str or not latest_str:
        return "up-to-date"

    clean_inst = str(installed_str).strip().lstrip("v").split("+")[0]
    clean_late = str(latest_str).strip().lstrip("v").split("+")[0]

    if clean_inst == clean_late or clean_late in {"0.0.0", "unknown", ""}:
        return "up-to-date"

    cmp = compare_versions(installed_str, latest_str)
    if cmp >= 0:
        return "up-to-date"

    t_inst = parse_semver(installed_str)
    t_late = parse_semver(latest_str)

    if t_late[0] > t_inst[0] or t_late[1] > t_inst[1]:
        return "major"
    elif t_late[2] > t_inst[2]:
        return "minor"
    else:
        return "patch"


def determine_update_type(installed_ver, latest_same_major, latest_absolute):
    """Determines update type, returning minor-major or patch-major if both updates exist."""
    if not latest_absolute or str(latest_absolute).strip() in {"0.0.0", "unknown", ""}:
        return "up-to-date"
    if not installed_ver or str(installed_ver).strip() in {"0.0.0", "unknown", ""}:
        return "up-to-date"

    clean_inst = str(installed_ver).strip().lstrip("v").split("+")[0]
    clean_abs = str(latest_absolute).strip().lstrip("v").split("+")[0]
    if clean_inst == clean_abs:
        return "up-to-date"

    abs_type = classify_update(installed_ver, latest_absolute)
    if abs_type == "major" and latest_same_major and latest_same_major != installed_ver:
        clean_same = str(latest_same_major).strip().lstrip("v").split("+")[0]
        if clean_inst and clean_same and clean_inst != clean_same:
            same_major_type = classify_update(clean_inst, clean_same)
            if same_major_type in {"minor", "patch"}:
                return f"{same_major_type}-major"

    return abs_type


def find_latest_semver_tiers(installed_ver, all_versions):
    """Finds the latest patch, same-major (minor), and absolute (major) versions.
    Returns:
        (latest_patch, latest_same_major, latest_absolute)
    """
    if not installed_ver or not all_versions:
        return (None, None, None)

    clean_inst = RE_CLEAN_VER.sub("", installed_ver).split("+")[0]
    inst_parsed = parse_semver(clean_inst)
    inst_major = inst_parsed[1]
    inst_minor = inst_parsed[2]
    installed_is_prerelease = bool(inst_parsed[5])

    parsed_versions = []
    for v in all_versions:
        clean_v = RE_CLEAN_VER.sub("", v).split("+")[0]
        parsed_versions.append((v, parse_semver(clean_v)))

    filtered_versions = []
    for v, parsed in parsed_versions:
        if not installed_is_prerelease and parsed[5]:
            continue
        filtered_versions.append((v, parsed))

    if not filtered_versions:
        filtered_versions = parsed_versions

    def semver_sort_key(item):
        epoch, major, minor, patch, revision, prerelease = item[1]
        is_stable = 1 if not prerelease else 0
        return (
            epoch,
            major,
            minor,
            patch,
            revision,
            is_stable,
            PrereleaseKey(prerelease),
        )

    sorted_all = sorted(filtered_versions, key=semver_sort_key)
    if not sorted_all:
        return (None, None, None)

    latest_absolute = sorted_all[-1][0]

    same_major_versions = []
    same_patch_versions = []
    for v, parsed in sorted_all:
        if parsed[1] == inst_major:
            same_major_versions.append(v)
            if parsed[2] == inst_minor:
                same_patch_versions.append(v)

    latest_patch = same_patch_versions[-1] if same_patch_versions else None
    latest_same_major = same_major_versions[-1] if same_major_versions else None

    return (latest_patch, latest_same_major, latest_absolute)


def find_latest_same_major(installed_ver, all_versions):
    """Finds the latest version in all_versions that shares the same major version as installed_ver.
    Returns:
        (latest_same_major, latest_absolute)
    """
    _, latest_same_major, latest_absolute = find_latest_semver_tiers(
        installed_ver, all_versions
    )
    return (latest_same_major, latest_absolute)


def format_latest_versions(latest_same_major, latest_absolute):
    """Formats the latest version for display when they differ between same-major and absolute."""
    if not latest_absolute:
        return None
    if not latest_same_major or latest_same_major == latest_absolute:
        return latest_absolute
    return f"{latest_same_major} (latest: {latest_absolute})"


def clean_repo_url(url):
    """Normalizes repository URLs from different registries into clean web URLs."""
    if not url:
        return None
    if isinstance(url, dict):
        url = url.get("url") or ""
    if not isinstance(url, str):
        return None
    url = url.strip()

    if url.lower().startswith("javascript:"):
        return None

    url = url.removeprefix("git+")
    if url.startswith("git://"):
        url = "https://" + url[6:]
    elif url.startswith("git@"):
        url = url[4:]
        url = url.replace(":", "/")
        url = "https://" + url
    url = url.removesuffix(".git")
    url = url.replace("ssh://git@", "https://")
    url = url.rstrip("/")

    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            if url:
                url = "https://" + url
            parsed = urllib.parse.urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return None
    except Exception:
        return None

    return url


def is_github_url(url):
    """Safely checks if the URL hostname is github.com or a subdomain of it."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        return hostname == "github.com" or hostname.endswith(".github.com")
    except Exception:
        return False


def is_gitlab_url(url):
    """Safely checks if the URL hostname is gitlab.com or a subdomain of it."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        return hostname == "gitlab.com" or hostname.endswith(".gitlab.com")
    except Exception:
        return False


def get_compare_url(repo_url, installed, latest):
    """Generates a comparison diff link between installed and latest version."""
    repo_url = clean_repo_url(repo_url)
    if not repo_url or not installed or not latest:
        return None
    inst_clean = installed.lstrip("v")
    late_clean = latest.lstrip("v")
    if is_github_url(repo_url):
        return f"{repo_url}/compare/v{inst_clean}...v{late_clean}"
    elif is_gitlab_url(repo_url):
        return f"{repo_url}/-/compare/v{inst_clean}...v{late_clean}"
    return f"{repo_url}/compare/{inst_clean}...{late_clean}"


def _fetch_registry_json_or_xml(url, format="json"):
    """Helper to fetch and parse JSON or XML from a URL using safe_urlopen."""
    req = urllib.request.Request(url)
    with safe_urlopen(req, timeout=5) as response:
        raw_data = response.read()

    if format == "json":
        return json.loads(raw_data.decode("utf-8"))
    elif format == "xml":
        return safe_et_fromstring(raw_data)
    return raw_data


def resolve_npm_repo(name):
    """Fetches the repository URL for an NPM package from registry (lazy-loaded)."""
    try:
        url = f"{URL_NPM_REGISTRY}{urllib.parse.quote(name)}/latest"
        data = _fetch_registry_json_or_xml(url, format="json")
        repo = data.get("repository")
        return clean_repo_url(repo)
    except Exception as e:
        if DEBUG_MODE:
            print(
                f"{COLOR_YELLOW}{ICON_WARN} Debug: Failed to resolve NPM repository for '{name}': {e}{COLOR_RESET}"
            )
            traceback.print_exc(file=sys.stdout)
    return None


def resolve_nuget_repo(name, version):
    """Parses .nuspec XML to find the repository URL of a NuGet package."""
    try:
        name_lower = name.lower()
        url = f"{URL_NUGET_REGISTRY}{name_lower}/{version}/{name_lower}.nuspec"
        root = _fetch_registry_json_or_xml(url, format="xml")
        repo_url = None
        proj_url = None
        for elem in root.iter():
            tag_local = elem.tag.split("}")[-1]
            if tag_local == "repository":
                val = elem.attrib.get("url")
                if val:
                    repo_url = val
            elif tag_local == "projectUrl":
                if elem.text:
                    proj_url = elem.text.strip()
        if repo_url:
            return clean_repo_url(repo_url)
        if proj_url:
            return clean_repo_url(proj_url)
    except Exception as e:
        if DEBUG_MODE:
            print(
                f"{COLOR_YELLOW}{ICON_WARN} Debug: Failed to resolve NuGet repository for '{name}' (version {version}): {e}{COLOR_RESET}"
            )
            traceback.print_exc(file=sys.stdout)
    return None


def resolve_maven_repo(registry_url, group_path, artifact_id, version):
    """Parses .pom XML to find the repository or project URL of a Maven/Gradle package."""
    try:
        url = f"{registry_url}{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
        root = _fetch_registry_json_or_xml(url, format="xml")
        scm_url = None
        proj_url = None
        for elem in root.iter():
            tag_local = elem.tag.split("}")[-1]
            if tag_local == "scm":
                for child in elem:
                    child_tag = child.tag.split("}")[-1]
                    if child_tag == "url":
                        scm_url = child.text
            elif tag_local == "url" and elem.text:
                proj_url = elem.text
        return clean_repo_url(scm_url or proj_url)
    except Exception as e:
        if DEBUG_MODE:
            print(
                f"{COLOR_YELLOW}{ICON_WARN} Debug: Failed to resolve Maven repository for '{group_path}:{artifact_id}' (version {version}) from {registry_url}: {e}{COLOR_RESET}"
            )
            traceback.print_exc(file=sys.stdout)
    return None


def resolve_go_repo(name):
    """Translates Go module names to their repository web URLs."""
    if not name or not isinstance(name, str):
        return ""
    parts = name.split("/")
    if len(parts) >= 3 and parts[0] == "github.com":
        return f"https://github.com/{parts[1]}/{parts[2]}"
    elif len(parts) >= 3 and parts[0] == "golang.org" and parts[1] == "x":
        return f"https://github.com/golang/{parts[2]}"
    return f"https://{name}"


# ==============================================================================
# NPM Checker Logic
# ==============================================================================


def hex_to_base64(hex_str):
    """Converts a SHA-1 hexadecimal string to base64 with a 'sha1-' prefix."""
    try:
        raw_bytes = codecs.decode(hex_str.strip(), "hex")
        b64_bytes = base64.b64encode(raw_bytes)
        return "sha1-" + b64_bytes.decode("utf-8")
    except Exception:
        return None


def find_npm_files(base_path):
    """Finds package.json and lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml) in path."""
    pkg_path = os.path.join(base_path, "package.json")

    lock_files = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    lock_path = None
    for lf in lock_files:
        path = os.path.join(base_path, lf)
        if os.path.exists(path):
            lock_path = path
            break

    return (pkg_path if os.path.exists(pkg_path) else None, lock_path)


def format_yarn_berry_checksum(checksum_val):
    """Formats a Yarn Berry checksum to Subresource Integrity (SRI) format if possible."""
    # Remove cache version prefix, e.g. "10c0/" or "8/" or "10/"
    if "/" in checksum_val:
        checksum_val = checksum_val.split("/")[-1]

    # Check for sha512:, sha256:, or sha1: prefixes
    algo = None
    hash_str = checksum_val
    if checksum_val.startswith("sha512:"):
        algo = "sha512"
        hash_str = checksum_val[7:]
    elif checksum_val.startswith("sha256:"):
        algo = "sha256"
        hash_str = checksum_val[7:]
    elif checksum_val.startswith("sha1:"):
        algo = "sha1"
        hash_str = checksum_val[5:]
    elif len(checksum_val) == 128 and all(c in string.hexdigits for c in checksum_val):
        algo = "sha512"
    elif len(checksum_val) == 64 and all(c in string.hexdigits for c in checksum_val):
        algo = "sha256"
    elif len(checksum_val) == 40 and all(c in string.hexdigits for c in checksum_val):
        algo = "sha1"

    if algo and all(c in string.hexdigits for c in hash_str):
        try:
            raw_bytes = codecs.decode(hash_str.strip(), "hex")
            b64_bytes = base64.b64encode(raw_bytes)
            return f"{algo}-{b64_bytes.decode('utf-8')}"
        except (ValueError, UnicodeError):
            pass

    # Fallback to replacing colon with hyphen if it's already in sha512: or sha1: form
    if checksum_val.startswith("sha512:"):
        return checksum_val.replace("sha512:", "sha512-", 1)
    if checksum_val.startswith("sha256:"):
        return checksum_val.replace("sha256:", "sha256-", 1)
    if checksum_val.startswith("sha1:"):
        return checksum_val.replace("sha1:", "sha1-", 1)

    return checksum_val


def parse_yarn_lock(filepath):
    """Parses yarn.lock to extract resolved versions and their parent relations.
    Supports both Yarn Classic (v1) and Yarn Berry (v2, v3, v4).
    Returns:
        tuple: (resolved, parents, integrity) where integrity is (name, version) -> integrity_str
    """
    resolved = {}
    parents = {}
    integrity_dict = {}

    def extract_pkg_name(part):
        if not part:
            return ""
        if part.startswith("@"):
            # Scoped package, name starts with @. The separator is the next @
            parts = part[1:].split("@", 1)
            if len(parts) == 2:
                name = "@" + parts[0]
            else:
                name = part
        else:
            # Non-scoped package, separator is the first @
            parts = part.split("@", 1)
            if len(parts) == 2:
                name = parts[0]
            else:
                name = part

        name = name.removeprefix("npm:")
        return name

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            current_names = []
            current_version = None
            current_integrity = None
            in_dependencies = False
            dep_indent = None

            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                indent_len = len(line) - len(line.lstrip())

                # Check if we are at the top level (new package definition block)
                if indent_len == 0:
                    # Save the previous package block's integrity info if valid
                    if current_names and current_version and current_integrity:
                        for name in current_names:
                            integrity_dict[(name, current_version)] = current_integrity

                    # Reset package block state
                    in_dependencies = False
                    dep_indent = None
                    current_names = []
                    current_version = None
                    current_integrity = None

                    # If this is metadata or doesn't end with a colon, skip
                    if not line.rstrip().endswith(":") or "__metadata:" in line:
                        continue

                    header = stripped.rstrip(":")

                    # Parse the package specifier(s) in header, split by comma respecting quotes
                    parts = []
                    current_part = []
                    in_quotes = False
                    for char in header:
                        if char == '"':
                            in_quotes = not in_quotes
                        elif char == "," and not in_quotes:
                            parts.append("".join(current_part).strip())
                            current_part = []
                        else:
                            current_part.append(char)
                    if current_part:
                        parts.append("".join(current_part).strip())

                    for part in parts:
                        part = part.strip('"')
                        pkg_name = extract_pkg_name(part)
                        if pkg_name:
                            current_names.append(pkg_name)

                elif indent_len > 0:
                    # Manage exiting out of dependencies block based on relative indentation
                    if (
                        in_dependencies
                        and dep_indent is not None
                        and indent_len <= dep_indent
                    ):
                        in_dependencies = False
                        dep_indent = None

                    if in_dependencies:
                        # Parsing a dependency line
                        if ":" in stripped:
                            dep_name = stripped.split(":", 1)[0].strip().strip('"')
                        else:
                            dep_name = stripped.split(" ", 1)[0].strip().strip('"')
                        if dep_name:
                            for name in current_names:
                                parents.setdefault(dep_name, set()).add(name)
                    else:
                        # Parsing properties of the current package
                        if stripped.startswith(("version ", "version:")):
                            ver_val = (
                                stripped.split(" ", 1)[-1]
                                if " " in stripped
                                else stripped.split(":", 1)[-1]
                            )
                            ver_val = ver_val.strip().strip('"').strip(":").strip()
                            current_version = ver_val
                            for name in current_names:
                                resolved.setdefault(name, set()).add(ver_val)

                        elif stripped.startswith(("integrity ", "integrity:")):
                            integrity_val = (
                                stripped.split(" ", 1)[-1]
                                if " " in stripped
                                else stripped.split(":", 1)[-1]
                            )
                            integrity_val = (
                                integrity_val.strip().strip('"').strip(":").strip()
                            )
                            current_integrity = integrity_val

                        elif stripped.startswith(("checksum:", "checksum ")):
                            checksum_val = (
                                stripped.split(" ", 1)[-1]
                                if " " in stripped
                                else stripped.split(":", 1)[-1]
                            )
                            checksum_val = (
                                checksum_val.strip().strip('"').strip(":").strip()
                            )
                            current_integrity = format_yarn_berry_checksum(checksum_val)

                        elif any(
                            stripped.startswith(k)
                            for k in (
                                "dependencies:",
                                "optionalDependencies:",
                                "peerDependencies:",
                                "dependencies ",
                                "optionalDependencies ",
                                "peerDependencies ",
                            )
                        ):
                            if not stripped.rstrip().endswith("{}"):
                                in_dependencies = True
                                dep_indent = indent_len

            # Save the last package block's integrity info if valid
            if current_names and current_version and current_integrity:
                for name in current_names:
                    integrity_dict[(name, current_version)] = current_integrity

        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean, integrity_dict
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading yarn.lock: {e}{COLOR_RESET}")
        return {}, {}, {}


def parse_pnpm_lock(filepath):
    """Parses pnpm-lock.yaml to extract resolved versions and their parent relations.
    Returns:
        tuple: (resolved, parents, integrity) where integrity is (name, version) -> integrity_str
    """
    resolved = {}
    parents = {}
    integrity_dict = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            # The stack stores tuples of (indentation_level, state_name, context_data)
            # Valid state names: 'ROOT', 'PACKAGES', 'PACKAGE_BODY', 'DEPENDENCIES'
            stack = []
            current_pkg = None
            current_version = None

            for line in f:
                stripped = line.strip()
                if (
                    not stripped
                    or stripped.startswith("#")
                    or stripped == "---"
                    or stripped == "..."
                ):
                    continue

                indent = len(line) - len(line.lstrip())

                # Maintain the indentation stack: pop states that are at deeper indentation (preserving DEPENDENCIES at equal indent)
                while stack:
                    top_indent, top_state, _ = stack[-1]
                    if (
                        top_state in {"DEPENDENCIES", "IMPORTER_DEPS"}
                        and indent == top_indent
                    ):
                        break
                    if indent <= top_indent:
                        stack.pop()
                    else:
                        break

                current_state = stack[-1][1] if stack else "ROOT"
                current_pkg = None
                current_version = None
                for item in reversed(stack):
                    if item[1] == "PACKAGE_BODY" and item[2]:
                        current_pkg, current_version = item[2]
                        break

                # Check transition out/in of importers, packages, or snapshots block at root level
                if stripped.startswith("importers:"):
                    stack.append((indent, "IMPORTERS", None))
                    continue
                elif stripped.startswith(("packages:", "snapshots:")):
                    stack.append((indent, "PACKAGES", None))
                    continue

                if current_state in {"IMPORTERS", "IMPORTER_ITEM", "IMPORTER_DEPS"}:
                    if stripped.startswith(
                        (
                            "dependencies:",
                            "devDependencies:",
                            "optionalDependencies:",
                            "peerDependencies:",
                        )
                    ):
                        while stack and stack[-1][1] in {
                            "IMPORTER_DEPS",
                            "IMPORTER_DEP_ITEM",
                        }:
                            stack.pop()
                        stack.append((indent, "IMPORTER_DEPS", None))
                        continue
                    elif stripped.endswith(":") and current_state in {
                        "IMPORTERS",
                        "IMPORTER_ITEM",
                    }:
                        imp_name = stripped.rstrip(":").strip("'\"")
                        base_name = imp_name.rsplit("/", 1)[-1]
                        parents.setdefault(imp_name, set()).add("root")
                        parents.setdefault(base_name, set()).add("root")
                        stack.append((indent, "IMPORTER_ITEM", imp_name))
                        continue

                if current_state == "IMPORTER_DEPS":
                    if ":" in stripped:
                        dep_name = stripped.split(":", 1)[0].strip().strip("'\"")
                        if (
                            dep_name
                            and dep_name not in {"specifier", "version"}
                            and dep_name
                            not in {"node", "npm", "pnpm", "yarn", "bun", "python"}
                        ):
                            parents.setdefault(dep_name, set()).add("root")
                            stack.append((indent, "IMPORTER_DEP_ITEM", dep_name))

                elif current_state == "PACKAGES":
                    # We are expecting package definitions as keys, e.g., '/direct-dep@1.0.1:'
                    # Remove trailing empty object if present, e.g. "key: {}" -> "key:"
                    raw_line = stripped
                    if raw_line.endswith("{}"):
                        raw_line = raw_line[:-2].rstrip()
                    raw_pkg = raw_line.rstrip(":").strip("'\"")
                    raw_pkg = raw_pkg.removeprefix("/")
                    if "node_modules/" in raw_pkg:
                        raw_pkg = raw_pkg.split("node_modules/")[-1]
                    if "/" in raw_pkg and not raw_pkg.startswith("@"):
                        first_part = raw_pkg.split("/", 1)[0]
                        if "." in first_part or "localhost" in first_part:
                            raw_pkg = raw_pkg.split("/", 1)[1]

                    pkg_name = None
                    version = None

                    # Robust separator '@' detection dividing package name from version/peer info
                    if raw_pkg.startswith("@"):
                        at_idx = raw_pkg.find("@", 1)
                    else:
                        at_idx = raw_pkg.find("@")

                    if at_idx != -1:
                        pkg_name = raw_pkg[:at_idx]
                        version = raw_pkg[at_idx + 1 :]

                    if not pkg_name and "/" in raw_pkg:
                        parts = raw_pkg.rsplit("/", 1)
                        if len(parts) == 2:
                            pkg_name = parts[0]
                            version = parts[1]

                    if not pkg_name:
                        pkg_name = raw_pkg
                        version = "unknown"

                    if version and "(" in version:
                        version = version.split("(", 1)[0]

                    if (
                        pkg_name
                        and version
                        and pkg_name
                        not in {"node", "npm", "pnpm", "yarn", "bun", "python"}
                    ):
                        resolved.setdefault(pkg_name, set()).add(version)
                        # Push this package's context onto the stack
                        stack.append((indent, "PACKAGE_BODY", (pkg_name, version)))

                if current_state in {"PACKAGE_BODY", "DEPENDENCIES"}:
                    if stripped.startswith(
                        (
                            "dependencies:",
                            "devDependencies:",
                            "optionalDependencies:",
                            "peerDependencies:",
                        )
                    ):
                        while stack and stack[-1][1] in {
                            "DEPENDENCIES",
                            "DEPENDENCY_ITEM",
                        }:
                            stack.pop()
                        stack.append((indent, "DEPENDENCIES", None))
                        continue

                if current_state == "PACKAGE_BODY":
                    # Inside a package block. We check for integrity.
                    if "integrity" in stripped and current_version:
                        parts = stripped.split("integrity", 1)
                        if len(parts) == 2:
                            val = parts[1].strip()
                            if val.startswith(":"):
                                val = val[1:].strip()
                            val = val.strip("{}\"'").strip()
                            val = val.split()[0].strip(",}'\"")
                            if val:
                                integrity_dict[(current_pkg, current_version)] = val

                elif current_state == "DEPENDENCIES":
                    # We are in a list of dependencies under a package.
                    # Each line is: dependency_name: version
                    if ":" in stripped:
                        dep_name, _dep_ver = stripped.split(":", 1)
                        dep_name = dep_name.strip().strip("'\"")
                        if (
                            dep_name
                            and current_pkg
                            and dep_name
                            not in {"node", "npm", "pnpm", "yarn", "bun", "python"}
                            and dep_name
                            not in {
                                "specifier",
                                "version",
                                "integrity",
                                "optional",
                                "transitivePeerDependencies",
                            }
                        ):
                            parents.setdefault(dep_name, set()).add(current_pkg)
                            stack.append((indent, "DEPENDENCY_ITEM", dep_name))

        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean, integrity_dict
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading pnpm-lock.yaml: {e}{COLOR_RESET}"
        )
        return {}, {}, {}


def parse_package_json(filepath):
    """Parses package.json to extract direct dependencies."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        dependencies = data.get("dependencies", {})
        dev_dependencies = data.get("devDependencies", {})
        engines = data.get("engines", {})

        return {
            "dependencies": dependencies,
            "devDependencies": dev_dependencies,
            "all_direct": {**dependencies, **dev_dependencies},
            "engines": engines,
        }
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Error reading package.json: {e}{COLOR_RESET}")
        return None


def parse_package_lock(filepath):
    """Parses package-lock.json to extract resolved versions and their parent relations.
    Returns:
        tuple: (resolved, parents, integrity, direct_versions) where integrity is (name, version) -> integrity_str
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        resolved = {}
        parents = {}
        integrity_dict = {}
        direct_versions = {}

        # 1. Parse packages key (v2 and v3 lockfiles)
        if "packages" in data and isinstance(data["packages"], dict):
            # Map path to package name
            path_to_name = {}
            for pkg_path in data["packages"]:
                if pkg_path == "":
                    path_to_name[pkg_path] = "root"
                    continue
                parts = pkg_path.split("node_modules/")
                if parts:
                    path_to_name[pkg_path] = parts[-1]

            for pkg_path, pkg_info in data["packages"].items():
                if not pkg_path:
                    continue
                parts = pkg_path.split("node_modules/")
                if len(parts) > 1:
                    pkg_name = parts[-1]
                    version = pkg_info.get("version")
                    if pkg_name and version:
                        resolved.setdefault(pkg_name, set()).add(version)
                        integrity = pkg_info.get("integrity")
                        if integrity:
                            integrity_dict[(pkg_name, version)] = integrity
                        if len(parts) == 2 and parts[0] == "":
                            direct_versions[pkg_name] = version

                    # Build parents map
                    deps = pkg_info.get("dependencies", {})
                    dev_deps = pkg_info.get("devDependencies", {})
                    peer_deps = pkg_info.get("peerDependencies", {})
                    opt_deps = pkg_info.get("optionalDependencies", {})
                    all_deps = {**deps, **dev_deps, **peer_deps, **opt_deps}
                    for child_name in all_deps:
                        parents.setdefault(child_name, set()).add(pkg_name)

            # Root & workspace package dependencies
            for pkg_path, pkg_info in data["packages"].items():
                if isinstance(pkg_info, dict) and "node_modules/" not in pkg_path:
                    ws_deps = {
                        **pkg_info.get("dependencies", {}),
                        **pkg_info.get("devDependencies", {}),
                        **pkg_info.get("peerDependencies", {}),
                        **pkg_info.get("optionalDependencies", {}),
                    }
                    for child_name in ws_deps:
                        parents.setdefault(child_name, set()).add("root")

        # 2. Parse dependencies key (v1 and v2 fallback)
        if "dependencies" in data and isinstance(data["dependencies"], dict):

            def recurse_v1_deps(deps_dict, parent_name="root"):
                for pkg_name, pkg_info in deps_dict.items():
                    if not isinstance(pkg_info, dict):
                        continue
                    version = pkg_info.get("version")
                    if version:
                        resolved.setdefault(pkg_name, set()).add(version)
                        integrity = pkg_info.get("integrity")
                        if integrity:
                            integrity_dict[(pkg_name, version)] = integrity
                        if parent_name == "root":
                            direct_versions[pkg_name] = version
                    parents.setdefault(pkg_name, set()).add(parent_name)

                    if "dependencies" in pkg_info and isinstance(
                        pkg_info["dependencies"], dict
                    ):
                        recurse_v1_deps(pkg_info["dependencies"], pkg_name)

            recurse_v1_deps(data["dependencies"])

        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean, integrity_dict, direct_versions
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading package-lock.json: {e}{COLOR_RESET}"
        )
        return {}, {}, {}, {}


def build_check_targets(pkg_data, lock_data, check_all):
    """Builds list of targets to scan."""
    targets = []

    if check_all:
        all_packages = set(lock_data.keys())
        if pkg_data:
            all_packages.update(pkg_data["all_direct"].keys())

        for name in sorted(all_packages):
            declared = None
            if pkg_data and name in pkg_data["all_direct"]:
                declared = pkg_data["all_direct"][name]
            installed = lock_data.get(name, [])
            targets.append({"name": name, "declared": declared, "installed": installed})
    else:
        if not pkg_data:
            print(
                f"{COLOR_RED}{ICON_ERROR} Cannot check direct dependencies: package.json is missing.{COLOR_RESET}"
            )
            return []

        for name, declared in sorted(pkg_data["all_direct"].items()):
            installed = lock_data.get(name, [])
            targets.append({"name": name, "declared": declared, "installed": installed})

    return targets


def find_direct_installed_version(
    pkg_name, declared_constraint, installed_versions, direct_versions_from_lock=None
):
    """
    Given a package name, its declared constraint, and list of installed versions,
    identifies which version is the direct install.
    """
    if not installed_versions:
        return None
    if len(installed_versions) == 1:
        return installed_versions[0]

    # If the lockfile parser explicitly identified the top-level direct version, use that!
    if direct_versions_from_lock and pkg_name in direct_versions_from_lock:
        v = direct_versions_from_lock[pkg_name]
        if v in installed_versions:
            return v

    # Fallback 1: The version that satisfies the declared constraint
    if declared_constraint:
        try:
            satisfying = [
                v
                for v in installed_versions
                if check_semver_satisfies(v, declared_constraint)
            ]
            if len(satisfying) == 1:
                return satisfying[0]
            elif len(satisfying) > 1:
                return max(satisfying, key=parse_semver)
        except (ValueError, TypeError, KeyError):
            pass

    # Fallback 2: The highest installed version
    try:
        return max(installed_versions, key=parse_semver)
    except (ValueError, TypeError):
        return installed_versions[-1]


def check_npm_package(target):
    """Queries npm registry for package metadata and checks target version."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]

    # Helper to check if a version string is explicitly local
    def is_local_version(ver_str):
        if not ver_str:
            return False
        v = ver_str.strip()
        return (
            v.startswith(("file:", "link:", "portal:", "workspace:", "./", "../", "/"))
        )

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    try:
        # Properly URL-encode scoped packages (e.g. @babel/core -> @babel%2Fcore)
        if name.startswith("@"):
            parts = name.split("/")
            if len(parts) == 2:
                encoded_name = f"{parts[0]}%2F{parts[1]}"
            else:
                encoded_name = urllib.parse.quote(name)
        else:
            encoded_name = urllib.parse.quote(name)

        url = f"{URL_NPM_REGISTRY}{encoded_name}"
        req = urllib.request.Request(url)
        # Use abbreviated metadata format header
        req.add_header("Accept", "application/vnd.npm.install-v1+json")

        with safe_urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        latest_version = data.get("dist-tags", {}).get("latest")
        all_versions_meta = data.get("versions", {})
        all_versions = list(all_versions_meta.keys())

        for ver_str in versions_to_check:
            # If the version itself is explicitly local, we treat it as Local/local
            if is_local_version(ver_str):
                results.append(
                    {
                        "name": name,
                        "declared": declared,
                        "installed": ver_str,
                        "latest": "Local",
                        "latest_same_major": None,
                        "latest_absolute": None,
                        "status": "local",
                        "deprecated": None,
                        "error": None,
                        "repo_url": None,
                        "compare_url": None,
                        "releases_url": None,
                        "mismatch_checksum": False,
                        "lockfile_checksum": None,
                        "registry_checksums": [],
                    }
                )
                continue

            # Strip ranges prefixes to get base version for check
            clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"

            ver_meta = (
                all_versions_meta.get(clean_ver) or all_versions_meta.get(ver_str) or {}
            )
            deprecation_msg = ver_meta.get("deprecated")

            # Check lockfile integrity against registry integrity/shasum
            lockfile_integrity = target.get("integrity", {}).get(ver_str)
            mismatch = False
            reg_hashes = []
            if lockfile_integrity:
                lock_clean = lockfile_integrity.strip().lower()
                dist = ver_meta.get("dist") or {}
                reg_integrity = dist.get("integrity", "").strip().lower()
                reg_shasum = dist.get("shasum", "").strip().lower()

                reg_hashes = [
                    h.strip().lower() for h in reg_integrity.split() if h.strip()
                ]
                if reg_shasum:
                    reg_shasum_b64 = hex_to_base64(reg_shasum)
                    if reg_shasum_b64:
                        reg_hashes.append(reg_shasum_b64.lower())

                if reg_hashes and lock_clean not in reg_hashes:
                    mismatch = True

            # Find latest same major and absolute latest
            latest_same_major, latest_absolute = find_latest_same_major(
                clean_ver, all_versions
            )
            if latest_version:
                latest_absolute = latest_version
            if not latest_same_major:
                latest_same_major = latest_absolute

            update_type = determine_update_type(
                clean_ver, latest_same_major, latest_absolute
            )

            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in {"major", "minor-major", "patch-major"}:
                repo_url = resolve_npm_repo(name)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = (
                        f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    )

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": display_latest,
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": update_type,
                    "deprecated": deprecation_msg,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                    "mismatch_checksum": mismatch,
                    "lockfile_checksum": lockfile_integrity,
                    "registry_checksums": reg_hashes,
                }
            )

    except urllib.error.HTTPError as e:
        if e.code == 404:
            for ver_str in versions_to_check:
                results.append(
                    {
                        "name": name,
                        "declared": declared,
                        "installed": ver_str,
                        "latest": "Local",
                        "latest_same_major": None,
                        "latest_absolute": None,
                        "status": "local",
                        "deprecated": None,
                        "error": None,
                        "repo_url": None,
                        "compare_url": None,
                        "releases_url": None,
                        "mismatch_checksum": False,
                        "lockfile_checksum": target.get("integrity", {}).get(ver_str),
                        "registry_checksums": [],
                    }
                )
        else:
            error_msg = f"HTTP {e.code}"
            for ver_str in versions_to_check:
                results.append(
                    {
                        "name": name,
                        "declared": declared,
                        "installed": ver_str,
                        "latest": None,
                        "status": "error",
                        "deprecated": None,
                        "error": error_msg,
                        "mismatch_checksum": False,
                        "lockfile_checksum": target.get("integrity", {}).get(ver_str),
                        "registry_checksums": [],
                    }
                )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": str(e),
                    "mismatch_checksum": False,
                    "lockfile_checksum": target.get("integrity", {}).get(ver_str),
                    "registry_checksums": [],
                }
            )

    return results


def check_all_targets(targets, max_workers):
    """Executes checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(
        targets, check_npm_package, f"{COLOR_GRAY}[Progress: NPM check]", max_workers
    )


# ==============================================================================
# OSV Vulnerability Scanning Logic
# ==============================================================================


def check_osv_vulnerabilities(targets, ecosystem, max_workers=10):
    """Checks vulnerabilities for all targets using OSV querybatch API.
    Returns a dict mapping (package_name, version) -> list of hydrated vulnerability dicts.
    """
    print(
        f"{COLOR_BOLD}{COLOR_CYAN}Querying OSV vulnerability database...{COLOR_RESET}\n"
    )

    queries = []
    query_mapping = []

    for t in targets:
        name = t["name"]
        declared = t["declared"]
        installed_versions = t["installed"]

        versions_to_check = installed_versions if installed_versions else [declared]
        for ver_str in versions_to_check:
            # Clean range prefix symbols
            clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"

            queries.append(
                {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": clean_ver,
                }
            )
            query_mapping.append((name, ver_str, clean_ver))

    if not queries:
        return {}

    results_list = []
    chunk_size = 1000
    total_queries = len(queries)
    for i in range(0, total_queries, chunk_size):
        chunk_queries = queries[i : i + chunk_size]
        current_count = min(i + chunk_size, total_queries)
        sys.stdout.write(
            f"\r{COLOR_GRAY}[OSV] Sending batch query: {current_count}/{total_queries} packages...{COLOR_RESET}\033[K"
        )
        sys.stdout.flush()
        try:
            url = URL_OSV_QUERYBATCH
            req = urllib.request.Request(
                url,
                data=json.dumps({"queries": chunk_queries}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )

            with safe_urlopen(req, timeout=15) as response:
                res_data = json.loads(response.read().decode("utf-8"))

            results_list.extend(res_data.get("results", []))
        except Exception as e:
            sys.stdout.write("\n")
            print(
                f"{COLOR_RED}{ICON_ERROR} Failed to query OSV database batch: {e}{COLOR_RESET}"
            )
            # Extend results_list with empty results to maintain index alignment with query_mapping
            results_list.extend([{"vulns": []}] * len(chunk_queries))

    # Process batch results and collect vulnerability details
    hydrated_details = {}
    package_to_vuln_ids = {}

    total_results = len(results_list)
    for i, res in enumerate(results_list):
        if i >= len(query_mapping):
            break
        name, ver_str, clean_ver = query_mapping[i]

        sys.stdout.write(
            f"\r{COLOR_GRAY}[OSV] Hydrating in-memory structures: {i + 1}/{total_results} packages...{COLOR_RESET}\033[K"
        )
        sys.stdout.flush()

        vulns = res.get("vulns", [])

        # Hydrate subsequent pages if next_page_token is present
        next_page_token = res.get("next_page_token")
        while next_page_token:
            try:
                url = "https://api.osv.dev/v1/query"
                payload = {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": clean_ver,
                    "page_token": next_page_token,
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with safe_urlopen(req, timeout=10) as page_response:
                    page_data = json.loads(page_response.read().decode("utf-8"))
                additional_vulns = page_data.get("vulns", [])
                vulns.extend(additional_vulns)
                next_page_token = page_data.get("next_page_token")
            except Exception:
                break

        if vulns:
            ids = []
            for vuln in vulns:
                if "id" in vuln:
                    vuln_id = vuln["id"]
                    ids.append(vuln_id)
                    hydrated_details[vuln_id] = vuln
            package_to_vuln_ids[(name, clean_ver)] = ids

    # Clean current line after in-memory hydration
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

    # Identify any orphaned IDs that might need fallback fetching
    all_vuln_ids = set()
    for ids in package_to_vuln_ids.values():
        all_vuln_ids.update(ids)

    orphaned_ids = sorted(
        [
            vid
            for vid in all_vuln_ids
            if vid not in hydrated_details or "summary" not in hydrated_details[vid]
        ]
    )

    if orphaned_ids:
        completed = 0
        total_orphaned = len(orphaned_ids)

        def fetch_vuln_detail(vuln_id):
            try:
                url = f"{URL_OSV_VULNS}{vuln_id}"
                req = urllib.request.Request(url)
                with safe_urlopen(req, timeout=10) as response:
                    return vuln_id, json.loads(response.read().decode("utf-8"))
            except Exception as e:
                return vuln_id, {
                    "id": vuln_id,
                    "summary": f"Failed to fetch details: {e}",
                    "severity": "UNKNOWN",
                }

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(fetch_vuln_detail, vid): vid for vid in orphaned_ids
            }
            for future in as_completed(futures):
                completed += 1
                vid = futures[future]
                sys.stdout.write(
                    f"\r{COLOR_GRAY}[Progress: {completed}/{total_orphaned}] Fetching missing advisory details for {vid}...{COLOR_RESET}\033[K"
                )
                sys.stdout.flush()

                vid_res, detail = future.result()
                hydrated_details[vid_res] = detail

        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    # Map back to packages
    package_to_vulns = {}
    for (name, clean_ver), vids in package_to_vuln_ids.items():
        vuln_list = []
        for vid in vids:
            vuln_data = hydrated_details.get(vid, {})

            def _extract_osv_severity(data_dict):
                sev = "UNKNOWN"
                if "severity" in data_dict and isinstance(data_dict["severity"], list):
                    for s in data_dict["severity"]:
                        if s.get("type") in {"CVSS_V4", "CVSS_V3", "CVSS_V2"}:
                            score = s.get("score")
                            if score:
                                score_str = str(score)
                                if score_str.startswith("CVSS"):
                                    sev = score_str
                                else:
                                    prefix = (
                                        "CVSS:4.0/"
                                        if s.get("type") == "CVSS_V4"
                                        else (
                                            "CVSS:3.0/"
                                            if s.get("type") == "CVSS_V3"
                                            else "CVSS:2.0/"
                                        )
                                    )
                                    sev = f"{prefix}{score_str}"
                            break
                if sev == "UNKNOWN":
                    db_specs = []
                    if isinstance(data_dict.get("database_specific"), dict):
                        db_specs.append(data_dict["database_specific"])
                    if isinstance(data_dict.get("affected"), list):
                        for aff in data_dict["affected"]:
                            if isinstance(aff, dict) and isinstance(
                                aff.get("database_specific"), dict
                            ):
                                db_specs.append(aff["database_specific"])
                    for db_spec in db_specs:
                        sev_val = db_spec.get("severity") or db_spec.get("cvss")
                        if sev_val:
                            sev = str(sev_val)
                            break
                        info_val = db_spec.get("informational")
                        if info_val:
                            sev = str(info_val).upper()
                            break
                return sev

            # Determine severity
            severity = _extract_osv_severity(vuln_data)

            summary = vuln_data.get("summary")
            details = vuln_data.get("details", "")

            # If severity is UNKNOWN or summary is missing/generic, try to resolve via aliases already in hydrated_details
            if (
                severity == "UNKNOWN" or not summary or summary == "No summary provided"
            ) and "aliases" in vuln_data:
                for alias in vuln_data["aliases"]:
                    alias_data = hydrated_details.get(alias)
                    if alias_data:
                        if severity == "UNKNOWN":
                            severity = _extract_osv_severity(alias_data)

                        if not summary or summary == "No summary provided":
                            summary = alias_data.get("summary")
                        if not details:
                            details = alias_data.get("details", "")

            vuln_list.append(
                {
                    "id": vid,
                    "summary": summary or "No summary provided",
                    "severity": severity,
                    "details": details or "",
                }
            )

        severity_order = {
            "malicious": 5,
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "unknown": 0,
        }
        vuln_list.sort(
            key=lambda v: severity_order.get(get_severity_level(v), 0), reverse=True
        )
        package_to_vulns[(name, clean_ver)] = vuln_list

    return package_to_vulns


def validate_suppressions_schema(data):
    """Manually validates the suppressions JSON data structure to avoid external dependencies."""
    if not isinstance(data, dict):
        raise ValueError("Root element of the JSON file must be a JSON object.")

    if "metadata" not in data:
        raise ValueError("Missing required root key: 'metadata'")
    if "suppressions" not in data:
        raise ValueError("Missing required root key: 'suppressions'")

    # Validate metadata
    metadata = data["metadata"]
    if not isinstance(metadata, dict):
        raise ValueError("'metadata' must be a JSON object.")

    for req_meta in ["version", "last_modified", "approved_by"]:
        if req_meta not in metadata:
            raise ValueError(f"Missing required metadata field: '{req_meta}'")
        if not isinstance(metadata[req_meta], str) or not metadata[req_meta].strip():
            raise ValueError(f"Metadata field '{req_meta}' must be a non-empty string.")

    # Validate version pattern (e.g. 1.0 or 1.0.0)
    version = metadata["version"].strip()
    if not re.match(r"^\d+\.\d+(\.\d+)?$", version):
        raise ValueError(
            f"Metadata version '{version}' is invalid. Must match pattern 'X.Y' or 'X.Y.Z'."
        )

    # Validate last_modified date
    last_mod_str = metadata["last_modified"].strip()
    try:
        datetime.strptime(last_mod_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(
            f"Metadata 'last_modified' '{last_mod_str}' is invalid. Must be in 'YYYY-MM-DD' format."
        )

    # Validate suppressions
    suppressions = data["suppressions"]
    if not isinstance(suppressions, list):
        raise ValueError("'suppressions' must be a JSON array.")

    allowed_reasons = {
        "NOT_AFFECTED_BY_VULNERABILITY",
        "VULNERABILITY_MITIGATED_BY_ENVIRONMENT",
        "COMPENSATING_CONTROL_IMPLEMENTED",
        "FALSE_POSITIVE",
        "ACCEPTED_TEMPORARY_RISK",
    }

    for idx, rule in enumerate(suppressions):
        if not isinstance(rule, dict):
            raise ValueError(f"Suppression rule at index {idx} must be a JSON object.")

        # Check required fields
        required_fields = ["id", "package", "reason", "justification", "expires_at"]
        for req_field in required_fields:
            if req_field not in rule:
                raise ValueError(
                    f"Suppression rule at index {idx} is missing required field: '{req_field}'"
                )
            if not isinstance(rule[req_field], str) or not rule[req_field].strip():
                raise ValueError(
                    f"Suppression rule field '{req_field}' at index {idx} must be a non-empty string."
                )

        # Validate reason enum
        reason = rule["reason"].strip()
        if reason not in allowed_reasons:
            raise ValueError(
                f"Suppression rule 'reason' at index {idx} is '{reason}'. "
                f"Must be one of: {', '.join(allowed_reasons)}"
            )

        # Validate expires_at date
        expires_at_str = rule["expires_at"].strip()
        try:
            datetime.strptime(expires_at_str, "%Y-%m-%d")
        except ValueError:
            raise ValueError(
                f"Suppression rule 'expires_at' at index {idx} is '{expires_at_str}'. "
                f"Must be in 'YYYY-MM-DD' format."
            )

        # Validate optional fields
        for opt_field in ["ecosystem", "created_by", "approved_by"]:
            if opt_field in rule:
                val = rule[opt_field]
                if val is not None:
                    if not isinstance(val, str) or not val.strip():
                        raise ValueError(
                            f"Optional field '{opt_field}' at index {idx} must be a non-empty string if specified."
                        )


def apply_vulnerability_suppressions(results, suppress_path, project_path=None):
    """Applies vulnerability suppressions from a JSON file.
    Suppressed vulnerabilities are moved from 'vulnerabilities' to 'suppressed_vulnerabilities'.
    """
    # Initialize suppressed_vulnerabilities key for all results regardless of suppression file existence
    for r in results:
        r["suppressed_vulnerabilities"] = []

    file_to_load = None
    if suppress_path:
        file_to_load = suppress_path
        if not os.path.exists(file_to_load):
            print(
                f"{COLOR_RED}{ICON_ERROR} Suppress file not found: {suppress_path}{COLOR_RESET}"
            )
            sys.exit(1)
    else:
        candidates = []
        if project_path:
            candidates.append(os.path.join(project_path, "kevlar-suppressions.json"))
        candidates.append("kevlar-suppressions.json")

        for cand in candidates:
            if os.path.exists(cand):
                file_to_load = cand
                break

    if not file_to_load:
        return

    print(
        f"{COLOR_BOLD}{COLOR_CYAN}Loading suppressions from {file_to_load}...{COLOR_RESET}"
    )
    try:
        with open(file_to_load, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(
            f"{COLOR_RED}{ICON_ERROR} Failed to parse suppressions file: {e}{COLOR_RESET}"
        )
        sys.exit(1)

    try:
        validate_suppressions_schema(data)
    except ValueError as e:
        print(
            f"{COLOR_RED}{ICON_ERROR} Suppressions file schema validation failed: {e}{COLOR_RESET}"
        )
        sys.exit(1)

    suppressions = data.get("suppressions", [])

    # Process and filter rules by expiration date
    active_rules = []
    today = date.today()
    for rule in suppressions:
        expires_at_str = rule["expires_at"].strip()
        try:
            expires_at_date = datetime.strptime(expires_at_str, "%Y-%m-%d").date()
        except ValueError:
            # Should already be caught by schema validation, but keep as safety fallback
            continue

        if expires_at_date < today:
            # Rule has expired, print a warning in COLOR_YELLOW and discard it
            print(
                f"{COLOR_YELLOW}{ICON_WARN} Suppression rule for package '{rule['package']}' (vuln: '{rule['id']}') expired on {expires_at_str} and was discarded.{COLOR_RESET}"
            )
            continue

        active_rules.append(rule)

    suppressed_count = 0
    for r in results:
        pkg_name = r["name"].lower()
        pkg_tech = r.get("technology", "").lower()
        active_vulns = []
        suppressed_vulns = []

        for vuln in r.get("vulnerabilities", []):
            vuln_id = vuln["id"].upper()

            matched_rule = None
            for rule in active_rules:
                # 1. Package must match exactly
                if rule["package"].strip().lower() != pkg_name:
                    continue
                # 2. Ecosystem must match if specified
                if rule.get("ecosystem"):
                    if rule["ecosystem"].strip().lower() != pkg_tech:
                        continue
                # 3. ID must match exactly or be wildcard '*'
                rule_id = rule["id"].strip().upper()
                if rule_id != "*" and rule_id != vuln_id:
                    continue

                matched_rule = rule
                break

            if matched_rule:
                # Enrich vulnerability with governance metadata
                vuln["suppressed_reason"] = matched_rule["reason"]
                vuln["justification"] = matched_rule["justification"]
                vuln["expires_at"] = matched_rule["expires_at"]
                if matched_rule.get("created_by"):
                    vuln["created_by"] = matched_rule["created_by"]
                if matched_rule.get("approved_by"):
                    vuln["approved_by"] = matched_rule["approved_by"]

                suppressed_vulns.append(vuln)
                suppressed_count += 1

                tech_suffix = f" ({pkg_tech})" if pkg_tech else ""
                print(
                    f"{COLOR_GRAY}[SUPPRESSED] Ignored {vuln['id']} for package '{r['name']}'{tech_suffix} (Reason: {matched_rule['reason']}){COLOR_RESET}"
                )
            else:
                active_vulns.append(vuln)

        r["vulnerabilities"] = active_vulns
        r["suppressed_vulnerabilities"] = suppressed_vulns

    if suppressed_count > 0:
        print(
            f"\n{COLOR_GREEN}{ICON_OK} Successfully suppressed {suppressed_count} vulnerability alerts.{COLOR_RESET}\n"
        )


def find_direct_parents(name, parents_map, direct_packages):
    """Finds which direct dependencies transitively required the given package."""
    visited = set()
    direct_parents = set()
    queue = [name]

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        curr_parents = parents_map.get(current, [])
        for p in curr_parents:
            if p in direct_packages:
                direct_parents.add(p)
            elif p == "root":
                if current != name:
                    direct_parents.add(current)
            else:
                queue.append(p)

    return direct_parents


def _prepare_npm_lock_data(lock_file):
    lock_data, parents_data, integrity_data, direct_versions_lock = {}, {}, {}, {}
    if lock_file:
        basename = os.path.basename(lock_file)
        if basename == "package-lock.json":
            print(f"{COLOR_GRAY}{ICON_INFO} Reading package-lock.json...{COLOR_RESET}")
            lock_data, parents_data, integrity_data, direct_versions_lock = (
                parse_package_lock(lock_file)
            )
        elif basename == "yarn.lock":
            print(f"{COLOR_GRAY}{ICON_INFO} Reading yarn.lock...{COLOR_RESET}")
            lock_data, parents_data, integrity_data = parse_yarn_lock(lock_file)
        elif basename == "pnpm-lock.yaml":
            print(f"{COLOR_GRAY}{ICON_INFO} Reading pnpm-lock.yaml...{COLOR_RESET}")
            lock_data, parents_data, integrity_data = parse_pnpm_lock(lock_file)
    return lock_data, parents_data, integrity_data, direct_versions_lock


def _isolate_direct_npm_results(results, pkg_data, direct_versions_lock):
    if not (pkg_data and "all_direct" in pkg_data):
        return
    by_name = {}
    for idx, r in enumerate(results):
        if not r.get("is_engine", False):
            by_name.setdefault(r["name"], []).append(idx)

    for name, indices in by_name.items():
        if name in pkg_data["all_direct"] and len(indices) > 1:
            declared_constraint = pkg_data["all_direct"][name]
            installed_versions = [results[idx]["installed"] for idx in indices]
            direct_ver = find_direct_installed_version(
                name,
                declared_constraint,
                installed_versions,
                direct_versions_from_lock=direct_versions_lock,
            )
            for idx in indices:
                if results[idx]["installed"] != direct_ver:
                    results[idx]["declared"] = None


def _check_npm_integrity(results, lock_file, integrity_data):
    for r in results:
        r["missing_checksum"] = False
        r["weak_checksum"] = False
        if r.get("is_engine", False):
            continue

        if lock_file:
            key = (r["name"], r["installed"])
            if integrity_data.get(key):
                integrity_str = integrity_data[key].lower()
                if "sha512-" in integrity_str or "sha256-" in integrity_str:
                    pass
                elif "sha1-" in integrity_str:
                    r["weak_checksum"] = True
                else:
                    r["missing_checksum"] = True
            else:
                r["missing_checksum"] = True


def _check_npm_vulnerabilities(results, targets, args):
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["npm"]
        osv_vulns = check_osv_vulnerabilities(
            targets, tech_info["osv_ecosystem"], args.concurrent
        )
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []


def _add_node_constraint_result(results, node_constraint):
    if not node_constraint:
        return
    status, deprecated_msg, error_msg, recommendation = analyze_node_constraint(
        node_constraint
    )
    results.append(
        {
            "name": "node",
            "declared": node_constraint,
            "installed": "N/A",
            "latest": recommendation,
            "latest_same_major": None,
            "latest_absolute": None,
            "status": status,
            "deprecated": deprecated_msg,
            "error": error_msg,
            "repo_url": "https://nodejs.org",
            "compare_url": None,
            "releases_url": "https://nodejs.org/en/about/previous-releases",
            "mismatch_checksum": False,
            "lockfile_checksum": None,
            "registry_checksums": [],
            "is_engine": True,
        }
    )


def _resolve_npm_dependency_types(results, pkg_data, parents_data):
    direct_packages = (
        set(pkg_data["all_direct"].keys())
        if pkg_data and "all_direct" in pkg_data
        else set()
    )
    if parents_data:
        root_parents = {name for name, pts in parents_data.items() if "root" in pts}
        direct_packages.update(root_parents)

    for r in results:
        if not r.get("is_engine", False):
            if r["name"] in direct_packages:
                dev_deps = pkg_data.get("devDependencies", {}) if pkg_data else {}
                r["dep_type"] = "Dev" if r["name"] in dev_deps else "Direct"
                r["required_by"] = []
            else:
                r["dep_type"] = "Transitive"
                direct_parents = find_direct_parents(
                    r["name"], parents_data, direct_packages
                )
                r["required_by"] = sorted(direct_parents - {r["name"]})
        else:
            r["dep_type"] = "Engine"
            r["required_by"] = []


def _assign_npm_integrity_to_targets(targets, integrity_data):
    for t in targets:
        t_integrity = {}
        for ver in t["installed"]:
            key = (t["name"], ver)
            if key in integrity_data:
                t_integrity[ver] = integrity_data[key]
        t["integrity"] = t_integrity


def run_npm_checker(args):
    """Main orchestrator for npm checker."""
    pkg_file, lock_file = find_npm_files(args.path)

    if not pkg_file and not lock_file:
        print(
            f"{COLOR_RED}{ICON_ERROR} No package.json or lockfile found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    pkg_data = None
    if pkg_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading package.json...{COLOR_RESET}")
        pkg_data = parse_package_json(pkg_file)

    lock_data, parents_data, integrity_data, direct_versions_lock = (
        _prepare_npm_lock_data(lock_file)
    )

    targets = build_check_targets(pkg_data, lock_data, args.all)
    _assign_npm_integrity_to_targets(targets, integrity_data)

    node_constraint, _source = find_node_constraint(args.path, pkg_data)

    if not targets and not node_constraint:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    results = check_all_targets(targets, args.concurrent) if targets else []

    _isolate_direct_npm_results(results, pkg_data, direct_versions_lock)
    _check_npm_integrity(results, lock_file, integrity_data)
    _check_npm_vulnerabilities(results, targets, args)
    _add_node_constraint_result(results, node_constraint)
    _resolve_npm_dependency_types(results, pkg_data, parents_data)

    elapsed = time.time() - start_time

    return results, pkg_data, elapsed


# ==============================================================================
# PIP Checker Logic
# ==============================================================================


def parse_version_to_tuple_marker(v_str):
    """Parses a version string into a tuple of integers for environment marker comparison."""
    v_str = re.sub(r"^[^\d]+", "", v_str)
    parts = []
    for part in v_str.split("."):
        m = RE_NUM_START.match(part)
        if m:
            parts.append(int(m.group(1)))
        else:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def compare_versions_marker(left, op, right):
    """Compares two version strings based on the given operator for environment markers."""
    left_t = parse_version_to_tuple_marker(str(left))
    right_t = parse_version_to_tuple_marker(str(right))

    max_len = max(len(left_t), len(right_t))
    left_t += (0,) * (max_len - len(left_t))
    right_t += (0,) * (max_len - len(right_t))

    if op == "==" or op == "===":
        return left_t == right_t
    elif op == "!=":
        return left_t != right_t
    elif op == "<":
        return left_t < right_t
    elif op == "<=":
        return left_t <= right_t
    elif op == ">":
        return left_t > right_t
    elif op == ">=":
        return left_t >= right_t
    elif op == "~=":
        if left_t < right_t:
            return False
        right_orig_parts = [int(p) for p in re.findall(r"\d+", str(right))]
        if len(right_orig_parts) > 1:
            upper_bound = list(right_t)
            idx = len(right_orig_parts) - 2
            if idx >= 0:
                upper_bound[idx] += 1
                for i in range(idx + 1, len(upper_bound)):
                    upper_bound[i] = 0
                return left_t < tuple(upper_bound)
            else:
                return left_t[0] == right_t[0]
        else:
            return left_t[0] == right_t[0]
    return False


def tokenize_marker(marker_str):
    """Tokenizes a PEP 508 environment marker string."""
    tokens = []
    pos = 0
    while pos < len(marker_str):
        match = RE_MARKER_TOKEN.match(marker_str, pos)
        if not match:
            char = marker_str[pos]
            if char.isspace():
                pos += 1
                continue
            raise ValueError(
                f"Unexpected character in marker: {char} at position {pos}"
            )
        token = match.group(1)
        tokens.append(token)
        pos = match.end()
    return tokens


def parse_and_evaluate_marker(marker_str, env):
    """Parses and evaluates a PEP 508 environment marker expression."""
    tokens = tokenize_marker(marker_str)
    if not tokens:
        return True

    idx = [0]

    def peek():
        if idx[0] < len(tokens):
            return tokens[idx[0]]
        return None

    def consume():
        val = peek()
        if val is not None:
            idx[0] += 1
        return val

    def parse_or():
        left = parse_and()
        while peek() == "or":
            consume()
            right = parse_and()
            left = left or right
        return left

    def parse_and():
        left = parse_not()
        while peek() == "and":
            consume()
            right = parse_not()
            left = left and right
        return left

    def parse_not():
        if peek() == "not":
            consume()
            val = parse_not()
            return not val
        return parse_comparison()

    def parse_comparison():
        left_val, left_name = parse_primary()
        op = peek()
        if op in {"==", "!=", "<=", ">=", "<", ">", "===", "~=", "in", "not in"}:
            consume()
            right_val, right_name = parse_primary()
            return evaluate_comparison_op(
                left_val, left_name, op, right_val, right_name
            )
        return bool(left_val)

    def parse_primary():
        token = consume()
        if token == "(":
            val = parse_or()
            if consume() != ")":
                raise ValueError("Unmatched parenthesis in marker expression")
            return (val, None)
        if token is None:
            raise ValueError("Unexpected end of expression")
        if (token.startswith('"') and token.endswith('"')) or (
            token.startswith("'") and token.endswith("'")
        ):
            return (token[1:-1], None)
        if token in env:
            return (env[token], token)
        return (token, None)

    result = parse_or()
    if idx[0] < len(tokens):
        raise ValueError(f"Trailing tokens in marker expression: {tokens[idx[0]:]}")
    return result


def evaluate_comparison_op(left_val, left_name, op, right_val, right_name):
    """Evaluates a single comparison operation for markers."""
    is_version = left_name in {
        "python_version",
        "python_full_version",
        "implementation_version",
        "platform_version",
    } or right_name in {
        "python_version",
        "python_full_version",
        "implementation_version",
        "platform_version",
    }

    if op in {"in", "not in"}:
        left_str = str(left_val)
        right_str = str(right_val)
        if op == "in":
            return left_str in right_str
        else:
            return left_str not in right_str

    if is_version and op in {"==", "!=", "<", "<=", ">", ">=", "~="}:
        return compare_versions_marker(left_val, op, right_val)

    left_str = str(left_val)
    right_str = str(right_val)
    if op == "==":
        return left_str == right_str
    elif op == "!=":
        return left_str != right_str
    elif op == "<":
        return left_str < right_str
    elif op == "<=":
        return left_str <= right_str
    elif op == ">":
        return left_str > right_str
    elif op == ">=":
        return left_str >= right_str
    elif op == "===":
        return left_str == right_str

    return False


def get_env_markers():
    """Builds environment markers dictionary for the current interpreter."""
    import platform

    py_version_tuple = platform.python_version_tuple()
    python_version = f"{py_version_tuple[0]}.{py_version_tuple[1]}"
    python_full_version = platform.python_version()

    impl_ver = ""
    if hasattr(sys, "implementation") and hasattr(sys.implementation, "version"):
        v = sys.implementation.version
        impl_ver = f"{v.major}.{v.minor}.{v.micro}"
        if v.releaselevel != "final":
            impl_ver += f"{v.releaselevel}{v.serial}"

    impl_name = ""
    if hasattr(sys, "implementation") and hasattr(sys.implementation, "name"):
        impl_name = sys.implementation.name

    return {
        "os_name": os.name,
        "sys_platform": sys.platform,
        "platform_machine": platform.machine(),
        "platform_python_implementation": platform.python_implementation(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_version": python_version,
        "python_full_version": python_full_version,
        "implementation_name": impl_name,
        "implementation_version": impl_ver,
        "extra": "",
    }


def parse_requirements_txt(filepath, seen_files=None, base_dir=None):
    """Parses requirements.txt to extract dependencies and parent traces, supporting PEP 508 and file inclusions."""
    if seen_files is None:
        seen_files = set()

    abs_filepath = os.path.abspath(filepath)

    if base_dir is None:
        # To avoid breaking existing functionality where subdirectories
        # include parent directories within the project root,
        # we determine the project root heuristically, or default to cwd.
        # But we'll allow the unit tests to set base_dir explicitly.
        # Defaulting base_dir to the current working directory works in most cases
        # as the script runs from the project root.
        base_dir = os.getcwd()

    if abs_filepath in seen_files:
        return {}, {}
    seen_files.add(abs_filepath)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        dependencies = {}
        parents = {}

        last_pkg = None

        # Preprocess lines to merge continuation lines (ending with \)
        merged_lines = []
        continuation = ""
        for line in lines:
            stripped = line.strip()
            if stripped.endswith("\\"):
                continuation += stripped[:-1].rstrip() + " "
            else:
                merged_lines.append(continuation + line)
                continuation = ""
        if continuation:
            merged_lines.append(continuation)

        for line in merged_lines:
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("#"):
                if stripped.startswith("# via") and last_pkg:
                    parent_part = stripped[5:].strip()
                    for p in parent_part.split(","):
                        p_clean = p.strip()
                        if p_clean:
                            parents.setdefault(last_pkg, set()).add(p_clean)
                continue

            comment = ""
            stripped_line = stripped
            if " #" in line:
                parts = line.split(" #", 1)
                stripped_line = parts[0].strip()
                comment = parts[1].strip()
            elif "#" in line and not any(
                scheme in line for scheme in ("http://", "https://", "git+")
            ):
                parts = line.split("#", 1)
                stripped_line = parts[0].strip()
                comment = parts[1].strip()

            # Handle file inclusions like '-r requirements.txt', '-c constraints.txt', or relative paths like '../requirements.txt'
            inc_target = None
            is_url = any(
                s in stripped_line
                for s in ("http://", "https://", "git+", "svn+", "hg+", "@")
            )
            if stripped_line.startswith(
                ("-r ", "-c ", "--requirement ", "--constraint ")
            ):
                inc_target = stripped_line.split(maxsplit=1)[1].strip()
            elif not is_url and (
                stripped_line.startswith((".", "/", "\\"))
                or stripped_line.endswith((".txt", ".in"))
            ):
                inc_target = stripped_line.lstrip("-e ").strip()

            if inc_target:
                inc_path = os.path.abspath(
                    os.path.join(os.path.dirname(abs_filepath), inc_target)
                )

                # Check path traversal: The included file must not escape the initial root base_dir
                if not _is_safe_path(base_dir, inc_path):
                    continue

                if (
                    os.path.exists(inc_path)
                    and os.path.isfile(inc_path)
                    and inc_path not in seen_files
                ):
                    inc_deps, inc_parents = parse_requirements_txt(
                        inc_path, seen_files, base_dir=base_dir
                    )
                    dependencies.update(inc_deps)
                    for k, v in inc_parents.items():
                        parents.setdefault(k, set()).update(v)
                continue

            if stripped_line.startswith("-"):
                continue

            # Separate the requirement from the environment marker (separated by semicolon)
            if ";" in stripped_line:
                parts = stripped_line.split(";", 1)
                req_part = parts[0].strip()
                marker_part = parts[1].strip()
            else:
                req_part = stripped_line
                marker_part = None

            # Parse package name, optional extras, and specifier/URL (PEP 508 names must start with alphanumeric)
            match = RE_PEP508_REQ.match(req_part)
            if not match:
                continue

            pkg_name = match.group(1)
            match.group(2)
            rest = match.group(3).strip()

            # Evaluate markers if present
            if marker_part:
                try:
                    env = get_env_markers()
                    if not parse_and_evaluate_marker(marker_part, env):
                        continue
                except Exception as e:
                    print(
                        f"{COLOR_YELLOW}{ICON_WARN} Warning evaluating marker '{marker_part}': {e}{COLOR_RESET}"
                    )

            # Extract version specification or URL
            if rest.startswith("@"):
                url_part = rest[1:].strip()
                version_spec = f"@ {url_part}"
            elif rest:
                version_spec = RE_PEP508_OP.sub(r"\1", rest)
            else:
                version_spec = "*"

            dependencies[pkg_name] = version_spec
            last_pkg = pkg_name

            if comment.startswith("via"):
                parent_part = comment[3:].strip()
                for p in parent_part.split(","):
                    p_clean = p.strip()
                    if p_clean:
                        parents.setdefault(pkg_name, set()).add(p_clean)

        return dependencies, {k: list(v) for k, v in parents.items()}
    except Exception as e:
        print(
            f"{COLOR_RED}{ICON_ERROR} Error reading requirements.txt: {e}{COLOR_RESET}"
        )
        return None, None


def check_pypi_package(target):
    """Queries PyPI registry for package metadata and checks target version."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    try:
        encoded_name = urllib.parse.quote(name)
        url = f"{URL_PYPI_REGISTRY}{encoded_name}/json"

        req = urllib.request.Request(url)
        with safe_urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        info = data.get("info", {})
        latest_version = info.get("version")
        releases = data.get("releases", {})
        all_versions = list(releases.keys())

        for ver_str in versions_to_check:
            # Clean version constraints prefixes
            clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"

            # Check yanking (deprecation)
            files_list = releases.get(clean_ver) or releases.get(ver_str) or []
            yanked_reason = None
            for file_info in files_list:
                if isinstance(file_info, dict) and file_info.get("yanked"):
                    yanked_reason = (
                        file_info.get("yanked_reason")
                        or "This release was yanked from PyPI."
                    )
                    break

            # Find latest same major and absolute latest
            latest_same_major, latest_absolute = find_latest_same_major(
                clean_ver, all_versions
            )
            if latest_version:
                latest_absolute = latest_version
            if not latest_same_major:
                latest_same_major = latest_absolute

            update_type = determine_update_type(
                clean_ver, latest_same_major, latest_absolute
            )

            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in {"major", "minor-major", "patch-major"}:
                urls = info.get("project_urls") or {}
                raw_url = None
                for key in ["Source", "Repository", "Code", "Homepage"]:
                    for k, v in urls.items():
                        if (
                            key.lower() in k.lower()
                            and v
                            and is_github_url(clean_repo_url(v))
                        ):
                            raw_url = v
                            break
                    if raw_url:
                        break
                if not raw_url:
                    hp = info.get("home_page")
                    if hp and is_github_url(clean_repo_url(hp)):
                        raw_url = hp
                if not raw_url:
                    for v in urls.values():
                        if v and is_github_url(clean_repo_url(v)):
                            raw_url = v
                            break
                if not raw_url:
                    raw_url = info.get("home_page") or urls.get("Homepage")
                repo_url = clean_repo_url(raw_url)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = (
                        f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    )

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": display_latest,
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": update_type,
                    "deprecated": yanked_reason,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                }
            )

    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": error_msg,
                }
            )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": str(e),
                }
            )

    return results


def check_all_pip_targets(targets, max_workers):
    """Executes PyPI checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(
        targets, check_pypi_package, f"{COLOR_GRAY}[Progress: PyPI check]", max_workers
    )


def find_pip_files(base_path):
    """Finds manifest and lockfile for python/pip technologies."""
    poetry_lock = os.path.join(base_path, "poetry.lock")
    pyproject = os.path.join(base_path, "pyproject.toml")
    if os.path.exists(poetry_lock) and os.path.exists(pyproject):
        return pyproject, poetry_lock, "poetry"

    pdm_lock = os.path.join(base_path, "pdm.lock")
    if os.path.exists(pdm_lock) and os.path.exists(pyproject):
        return pyproject, pdm_lock, "pdm"

    pipfile_lock = os.path.join(base_path, "Pipfile.lock")
    if os.path.exists(pipfile_lock):
        return None, pipfile_lock, "pipenv"

    req_file = os.path.join(base_path, "requirements.txt")
    if os.path.exists(req_file):
        return req_file, None, "pip"

    if os.path.exists(pyproject):
        return pyproject, None, "pyproject"

    return None, None, None


def _iter_lock_blocks(filepath):
    """Helper generator to read a lockfile line by line and yield blocks
    separated by [[package]].
    """
    current_block = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip() == "[[package]]":
                yield "".join(current_block)
                current_block = []
            else:
                current_block.append(line)
        yield "".join(current_block)


def parse_poetry_lock(filepath):
    """Parses poetry.lock to extract resolved versions and their parent relations.
    Returns:
        tuple: (resolved, parents) where parents is child_name -> list of parent_names
    """
    resolved = {}
    parents = {}
    try:
        blocks_gen = _iter_lock_blocks(filepath)
        next(blocks_gen, None)  # Skip the first block (before the first [[package]])
        for block in blocks_gen:
            lines = block.splitlines()
            name = None
            version = None
            in_deps = False

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("[[") or (
                    stripped.startswith("[")
                    and not stripped.startswith("[package.dependencies]")
                ):
                    in_deps = False
                if stripped.startswith("[package.dependencies]"):
                    in_deps = True
                    continue

                if not in_deps:
                    if stripped.startswith("name ="):
                        name = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                    elif stripped.startswith("version ="):
                        version = (
                            stripped.split("=", 1)[1].strip().strip('"').strip("'")
                        )
                else:
                    if "=" in stripped:
                        dep_name = (
                            stripped.split("=", 1)[0].strip().strip('"').strip("'")
                        )
                        if dep_name and name:
                            parents.setdefault(dep_name, set()).add(name)

            if name and version:
                resolved.setdefault(name, set()).add(version)

        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading poetry.lock: {e}{COLOR_RESET}"
        )
        return {}, {}


def parse_pdm_lock(filepath):
    """Parses pdm.lock to extract resolved versions and their parent relations.
    Returns:
        tuple: (resolved, parents) where parents is child_name -> list of parent_names
    """
    resolved = {}
    parents = {}
    try:
        blocks_gen = _iter_lock_blocks(filepath)
        next(blocks_gen, None)  # Skip the first block (before the first [[package]])
        for block in blocks_gen:
            lines = block.splitlines()
            name = None
            version = None
            in_deps = False

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("[[") or (
                    stripped.startswith("[")
                    and not stripped.startswith("dependencies =")
                ):
                    in_deps = False
                if stripped.startswith("dependencies = ["):
                    in_deps = True
                    continue

                if not in_deps:
                    if stripped.startswith("name ="):
                        name = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                    elif stripped.startswith("version ="):
                        version = (
                            stripped.split("=", 1)[1].strip().strip('"').strip("'")
                        )
                else:
                    if stripped == "]":
                        in_deps = False
                    else:
                        item = stripped.rstrip(",").strip().strip('"').strip("'")
                        if item:
                            match = re.match(r"^([a-zA-Z0-9\-_.]+)", item)
                            if match and name:
                                dep_name = match.group(1)
                                parents.setdefault(dep_name, set()).add(name)

            if name and version:
                resolved.setdefault(name, set()).add(version)

        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading pdm.lock: {e}{COLOR_RESET}")
        return {}, {}


def parse_pipfile_lock(filepath):
    """Parses Pipfile.lock to extract resolved versions.
    Returns:
        tuple: (resolved, parents)
    """
    resolved = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        for section in ["default", "develop"]:
            deps = data.get(section, {})
            for name, info in deps.items():
                if isinstance(info, dict) and "version" in info:
                    version = info["version"]
                    version = version.removeprefix("==")
                    resolved.setdefault(name, set()).add(version)

        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, {}
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading Pipfile.lock: {e}{COLOR_RESET}"
        )
        return {}, {}


def parse_pep508(dep_string):
    """Parses a PEP 508 dependency string.
    Returns:
        tuple: (package_name, version_specifier) or (None, None)
    """
    if not isinstance(dep_string, str):
        return None, None
    req_part = dep_string.split(";", 1)[0].strip()
    if not req_part:
        return None, None
    match = RE_PEP508_NAME.match(req_part)
    if not match:
        return None, None
    name = match.group(1)
    rest = match.group(2).strip()
    if rest.startswith("["):
        extra_match = RE_PEP508_EXTRA.match(rest)
        if extra_match:
            rest = extra_match.group(1).strip()
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1].strip()
    rest = RE_PEP508_OP.sub(r"\1", rest)
    version_spec = rest if rest else "*"
    return name, version_spec


def parse_pyproject_toml(filepath):
    """Parses pyproject.toml to extract direct dependencies.
    Returns:
        dict: name -> version_specifier
    """
    dependencies = {}
    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)

        def process_poetry_deps(deps_dict):
            if not isinstance(deps_dict, dict):
                return
            for k, v in deps_dict.items():
                if k.lower() == "python":
                    continue
                if isinstance(v, str):
                    dependencies[k] = v
                elif isinstance(v, dict):
                    ver = v.get("version")
                    dependencies[k] = ver if isinstance(ver, str) else "*"

        # 1. PEP 621 dependencies
        project = data.get("project", {})
        if isinstance(project, dict):
            proj_deps = project.get("dependencies")
            if isinstance(proj_deps, list):
                for dep in proj_deps:
                    name, spec = parse_pep508(dep)
                    if name:
                        dependencies[name] = spec
            opt_deps = project.get("optional-dependencies")
            if isinstance(opt_deps, dict):
                for group_list in opt_deps.values():
                    if isinstance(group_list, list):
                        for dep in group_list:
                            name, spec = parse_pep508(dep)
                            if name:
                                dependencies[name] = spec
            elif isinstance(opt_deps, list):
                for group_item in opt_deps:
                    if isinstance(group_item, dict):
                        for group_list in group_item.values():
                            if isinstance(group_list, list):
                                for dep in group_list:
                                    name, spec = parse_pep508(dep)
                                    if name:
                                        dependencies[name] = spec

        # 2. Poetry
        tool = data.get("tool", {})
        if isinstance(tool, dict):
            poetry = tool.get("poetry", {})
            if isinstance(poetry, dict):
                process_poetry_deps(poetry.get("dependencies"))

                group = poetry.get("group", {})
                if isinstance(group, dict):
                    for group_table in group.values():
                        if isinstance(group_table, dict):
                            process_poetry_deps(group_table.get("dependencies"))

                process_poetry_deps(poetry.get("dev-dependencies"))

            # 3. PDM
            pdm = tool.get("pdm", {})
            if isinstance(pdm, dict):
                pdm_dev = pdm.get("dev-dependencies")
                if isinstance(pdm_dev, list):
                    for dep in pdm_dev:
                        name, spec = parse_pep508(dep)
                        if name:
                            dependencies[name] = spec
                elif isinstance(pdm_dev, dict):
                    for k, v in pdm_dev.items():
                        if isinstance(v, list):
                            for dep in v:
                                name, spec = parse_pep508(dep)
                                if name:
                                    dependencies[name] = spec
                        else:
                            if k.lower() == "python":
                                continue
                            if isinstance(v, str):
                                dependencies[k] = v
                            elif isinstance(v, dict):
                                ver = v.get("version")
                                dependencies[k] = ver if isinstance(ver, str) else "*"

                pdm_deps = pdm.get("dependencies")
                if isinstance(pdm_deps, list):
                    for dep in pdm_deps:
                        name, spec = parse_pep508(dep)
                        if name:
                            dependencies[name] = spec
                elif isinstance(pdm_deps, dict):
                    for k, v in pdm_deps.items():
                        if isinstance(v, list):
                            for dep in v:
                                name, spec = parse_pep508(dep)
                                if name:
                                    dependencies[name] = spec
                        else:
                            if k.lower() == "python":
                                continue
                            if isinstance(v, str):
                                dependencies[k] = v
                            elif isinstance(v, dict):
                                ver = v.get("version")
                                dependencies[k] = ver if isinstance(ver, str) else "*"

        return dependencies
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading pyproject.toml: {e}{COLOR_RESET}"
        )
        return {}


def run_pip_checker(args):
    """Main orchestrator for pip checker."""
    manifest_file, lock_file, tech_type = find_pip_files(args.path)

    if not manifest_file and not lock_file:
        print(
            f"{COLOR_RED}{ICON_ERROR} No requirements.txt, poetry.lock, Pipfile.lock, or pyproject.toml found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    direct_deps = {}
    lock_deps = {}
    parents_data = {}

    if tech_type == "poetry":
        print(
            f"{COLOR_GRAY}{ICON_INFO} Reading pyproject.toml (Poetry)...{COLOR_RESET}"
        )
        direct_deps = parse_pyproject_toml(manifest_file)
        print(f"{COLOR_GRAY}{ICON_INFO} Reading poetry.lock...{COLOR_RESET}")
        lock_deps, parents_data = parse_poetry_lock(lock_file)
    elif tech_type == "pdm":
        print(f"{COLOR_GRAY}{ICON_INFO} Reading pyproject.toml (PDM)...{COLOR_RESET}")
        direct_deps = parse_pyproject_toml(manifest_file)
        print(f"{COLOR_GRAY}{ICON_INFO} Reading pdm.lock...{COLOR_RESET}")
        lock_deps, parents_data = parse_pdm_lock(lock_file)
    elif tech_type == "pipenv":
        print(f"{COLOR_GRAY}{ICON_INFO} Reading Pipfile.lock...{COLOR_RESET}")
        lock_deps, parents_data = parse_pipfile_lock(lock_file)
        direct_deps = {k: "*" for k in lock_deps}
    elif tech_type == "pyproject":
        print(f"{COLOR_GRAY}{ICON_INFO} Reading pyproject.toml...{COLOR_RESET}")
        direct_deps = parse_pyproject_toml(manifest_file)
    elif tech_type == "pip":
        print(f"{COLOR_GRAY}{ICON_INFO} Reading requirements.txt...{COLOR_RESET}")
        dependencies, parents_data = parse_requirements_txt(manifest_file)
        direct_deps = dependencies
        for name, spec in dependencies.items():
            version = spec[2:] if spec.startswith("==") else ""
            if version:
                lock_deps[name] = [version]

    targets = []
    if args.all and lock_deps:
        for name, versions in lock_deps.items():
            declared = direct_deps.get(name)
            targets.append({"name": name, "declared": declared, "installed": versions})
    else:
        for name, declared in sorted(direct_deps.items()):
            versions = lock_deps.get(name, [])
            if (
                not versions
                and declared
                and not any(c in declared for c in [">", "<", "~", "*", "^"])
            ):
                clean_ver = declared.removeprefix("==")
                versions = [clean_ver]
            targets.append({"name": name, "declared": declared, "installed": versions})

    if not targets:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No Python packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    results = check_all_pip_targets(targets, args.concurrent)

    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["pip"]
        osv_vulns = check_osv_vulnerabilities(
            targets, tech_info["osv_ecosystem"], args.concurrent
        )

        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []

    for r in results:
        parents_list = parents_data.get(r["name"], [])
        r["required_by"] = sorted(parents_list)

    all_direct = {}
    for r in results:
        parents_list = parents_data.get(r["name"], [])
        is_direct = True
        if parents_list:
            for p in parents_list:
                if not p.startswith("-r") and "requirements" not in p:
                    is_direct = False
                    break
        else:
            is_direct = r["name"] in direct_deps

        if is_direct:
            all_direct[r["name"]] = direct_deps.get(r["name"], "0.0.0")

    elapsed = time.time() - start_time

    pkg_data_deps = (
        {k: v[0] if isinstance(v, list) and v else v for k, v in lock_deps.items()}
        if lock_deps
        else direct_deps
    )

    return (
        results,
        {
            "dependencies": pkg_data_deps,
            "devDependencies": {},
            "all_direct": all_direct,
        },
        elapsed,
    )


# ==============================================================================
# NuGet Checker Logic
# ==============================================================================


def find_and_parse_cpm_versions(start_path):
    """Walks up from start_path looking for Directory.Packages.props and parses central versions."""
    current = os.path.abspath(start_path)
    if os.path.isfile(current):
        current = os.path.dirname(current)

    while True:
        cpm_file = os.path.join(current, "Directory.Packages.props")
        if os.path.exists(cpm_file):
            try:
                tree = safe_et_parse(cpm_file)
                root = tree.getroot()
                cpm_versions = {}
                for elem in root.iter():
                    tag_local = elem.tag.split("}")[-1]
                    if tag_local == "PackageVersion":
                        pkg_include = elem.get("Include") or elem.get("Update")
                        version = elem.get("Version")
                        if not version:
                            ver_elem = elem.find("Version")
                            if ver_elem is not None:
                                version = ver_elem.text
                        if pkg_include and version:
                            cpm_versions[pkg_include] = version
                return cpm_versions
            except Exception as e:
                print(
                    f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Directory.Packages.props: {e}{COLOR_RESET}"
                )

        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    return {}


def parse_sln_file(sln_path):
    """Parses a .sln or .slnx solution file to retrieve relative paths to all project files."""
    project_paths = []
    try:
        sln_dir = os.path.dirname(os.path.abspath(sln_path))
        if sln_path.lower().endswith(".slnx"):
            try:
                tree = safe_et_parse(sln_path)
                root = tree.getroot()
                for elem in root.iter("Project"):
                    rel_p = elem.get("Path")
                    if rel_p:
                        norm_path = rel_p.replace("\\", "/")
                        if norm_path.endswith((".csproj", ".vbproj", ".fsproj")):
                            full_path = os.path.abspath(
                                os.path.join(sln_dir, norm_path)
                            )
                            if _is_safe_path(sln_dir, full_path) and os.path.exists(
                                full_path
                            ):
                                project_paths.append(full_path)
            except Exception:
                with open(sln_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    content = f.read()
                matches = re.findall(r'Path\s*=\s*"([^"]+)"', content, re.IGNORECASE)
                for m in matches:
                    norm_path = m.replace("\\", "/")
                    if norm_path.endswith((".csproj", ".vbproj", ".fsproj")):
                        full_path = os.path.abspath(os.path.join(sln_dir, norm_path))
                        if _is_safe_path(sln_dir, full_path) and os.path.exists(
                            full_path
                        ):
                            project_paths.append(full_path)
        else:
            with open(sln_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                content = f.read()

            matches = RE_CSPROJ_SLN.findall(content)

            for m in matches:
                norm_path = m.replace("\\", "/")
                if norm_path.endswith((".csproj", ".vbproj", ".fsproj")):
                    full_path = os.path.abspath(os.path.join(sln_dir, norm_path))
                    if _is_safe_path(sln_dir, full_path) and os.path.exists(full_path):
                        project_paths.append(full_path)
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading solution file: {e}{COLOR_RESET}"
        )

    return project_paths


def find_nuget_files(path):
    """Finds Solution file (.sln / .slnx), MSBuild project files, and assets files."""
    sln_file = None
    manifests = []
    assets_files = []

    abs_path = os.path.abspath(path)
    if os.path.isfile(abs_path):
        if abs_path.lower().endswith((".sln", ".slnx")):
            sln_file = abs_path
        elif abs_path.endswith((".csproj", ".vbproj", ".fsproj", "packages.config")):
            manifests = [abs_path]
    elif os.path.isdir(abs_path):
        sln_candidates = [
            os.path.join(abs_path, f)
            for f in os.listdir(abs_path)
            if f.lower().endswith((".sln", ".slnx"))
        ]
        if sln_candidates:
            sln_file = sln_candidates[0]
        else:
            files = os.listdir(abs_path)
            for f in files:
                if (
                    f.endswith((".csproj", ".vbproj", ".fsproj"))
                    or f == "packages.config"
                ):
                    manifests = [os.path.join(abs_path, f)]
                    break

    if sln_file:
        print(
            f"{COLOR_GRAY}{ICON_INFO} Solution file detected: {os.path.basename(sln_file)}{COLOR_RESET}"
        )
        manifests = parse_sln_file(sln_file)

    for manifest in manifests:
        proj_dir = os.path.dirname(manifest)
        obj_dir = os.path.join(proj_dir, "obj")
        assets = os.path.join(obj_dir, "project.assets.json")
        if os.path.exists(assets):
            assets_files.append(assets)

    return manifests, assets_files


def parse_csproj_or_config(path, cpm_versions=None):
    """Finds and parses MSBuild project files (.csproj, .vbproj, .fsproj) or packages.config files in a directory."""
    dependencies = {}
    if cpm_versions is None:
        cpm_versions = find_and_parse_cpm_versions(path)

    config_file = os.path.join(path, "packages.config")
    if os.path.exists(config_file):
        try:
            tree = safe_et_parse(config_file)
            root = tree.getroot()
            for pkg in root.findall("package"):
                pkg_id = pkg.get("id")
                version = pkg.get("version")
                if pkg_id:
                    dependencies[pkg_id] = version or "*"
            return dependencies
        except Exception as e:
            print(
                f"{COLOR_YELLOW}{ICON_WARN} Warning parsing packages.config: {e}{COLOR_RESET}"
            )

    try:
        proj_files = [
            f for f in os.listdir(path) if f.endswith((".csproj", ".vbproj", ".fsproj"))
        ]
        if proj_files:
            csproj_path = os.path.join(path, proj_files[0])
            tree = safe_et_parse(csproj_path)
            root = tree.getroot()

            for elem in root.iter():
                tag_local = elem.tag.split("}")[-1]
                if tag_local == "PackageReference":
                    pkg_include = elem.get("Include") or elem.get("Update")
                    version = elem.get("Version")

                    if not version:
                        ver_elem = elem.find("Version")
                        if ver_elem is not None:
                            version = ver_elem.text

                    if pkg_include:
                        ver = version or cpm_versions.get(pkg_include) or "*"
                        dependencies[pkg_include] = ver

            return dependencies
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning parsing project files: {e}{COLOR_RESET}"
        )

    return {}


def parse_project_assets(filepath):
    """Parses project.assets.json to extract exact resolved versions and parent relationships."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        resolved = {}
        parents = {}

        libraries = data.get("libraries", {})
        for lib_key, lib_info in libraries.items():
            if lib_info.get("type") == "package":
                parts = lib_key.split("/")
                if len(parts) == 2:
                    name, version = parts
                    resolved.setdefault(name, set()).add(version)

        targets = data.get("targets", {})
        for target_libs in targets.values():
            for lib_key, lib_info in target_libs.items():
                parts = lib_key.split("/")
                if len(parts) != 2:
                    continue
                parent_name = parts[0]

                deps = lib_info.get("dependencies", {})
                for child_name in deps:
                    parents.setdefault(child_name, set()).add(parent_name)

        project_info = data.get("project", {})
        frameworks = project_info.get("frameworks", {})
        for fw_info in frameworks.values():
            deps = fw_info.get("dependencies", {})
            for child_name in deps:
                parents.setdefault(child_name, set()).add("root")

        resolved_clean = {k: list(v) for k, v in resolved.items()}
        parents_clean = {k: list(v) for k, v in parents.items()}
        return resolved_clean, parents_clean
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading project.assets.json: {e}{COLOR_RESET}"
        )
        return {}, {}


def check_nuget_package(target):
    """Queries NuGet registry for package metadata and checks target version."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    try:
        encoded_name = urllib.parse.quote(name.lower())
        url = f"{URL_NUGET_REGISTRY}{encoded_name}/index.json"

        req = urllib.request.Request(url)
        with safe_urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        versions_list = data.get("versions", [])

        stable_versions = []
        for v in versions_list:
            if "-" not in v:
                stable_versions.append(v)

        valid_versions = stable_versions if stable_versions else versions_list

        for ver_str in versions_to_check:
            clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"

            latest_same_major, latest_absolute = find_latest_same_major(
                clean_ver, valid_versions
            )
            if not latest_same_major:
                latest_same_major = latest_absolute

            update_type = determine_update_type(
                clean_ver, latest_same_major, latest_absolute
            )

            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in {"major", "minor-major", "patch-major"}:
                repo_url = resolve_nuget_repo(name, latest_absolute)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = (
                        f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    )

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": display_latest,
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": update_type,
                    "deprecated": None,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                }
            )

    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": error_msg,
                }
            )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": str(e),
                }
            )

    return results


def check_all_nuget_targets(targets, max_workers):
    """Executes NuGet checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(
        targets,
        check_nuget_package,
        f"{COLOR_GRAY}[Progress: NuGet check]",
        max_workers,
    )


def run_nuget_checker(args):
    """Main orchestrator for NuGet checker."""
    manifests, assets_files = find_nuget_files(args.path)

    if not manifests and not assets_files:
        print(
            f"{COLOR_RED}{ICON_ERROR} No C# / VB.NET project files or project.assets.json found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    pkg_data = {}
    print(
        f"{COLOR_GRAY}{ICON_INFO} Reading C# / VB.NET project references...{COLOR_RESET}"
    )
    for manifest in manifests:
        proj_dir = os.path.dirname(manifest)
        cpm_versions = find_and_parse_cpm_versions(proj_dir)
        proj_deps = parse_csproj_or_config(proj_dir, cpm_versions)
        pkg_data.update(proj_deps)

    lock_data = {}
    parents_data = {}
    if assets_files:
        print(
            f"{COLOR_GRAY}{ICON_INFO} Reading project.assets.json files...{COLOR_RESET}"
        )
        for assets_file in assets_files:
            proj_lock, proj_parents = parse_project_assets(assets_file)
            for k, v_list in proj_lock.items():
                lock_data.setdefault(k, set()).update(v_list)
            for k, p_list in proj_parents.items():
                parents_data.setdefault(k, set()).update(p_list)

        lock_data = {k: list(v) for k, v in lock_data.items()}
        parents_data = {k: list(v) for k, v in parents_data.items()}

    targets = build_check_targets(
        {"all_direct": pkg_data} if pkg_data else None, lock_data, args.all
    )

    if not targets:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    results = check_all_nuget_targets(targets, args.concurrent)

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["nuget"]
        osv_vulns = check_osv_vulnerabilities(
            targets, tech_info["osv_ecosystem"], args.concurrent
        )

        # Attach vulns back to results
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []

    # Resolve transitive dependency parents
    direct_packages = set(pkg_data.keys()) if pkg_data else set()
    for r in results:
        direct_parents = find_direct_parents(r["name"], parents_data, direct_packages)
        r["required_by"] = sorted(direct_parents - {r["name"]})

    elapsed = time.time() - start_time

    return (
        results,
        {"dependencies": pkg_data, "devDependencies": {}, "all_direct": pkg_data},
        elapsed,
    )


# ==============================================================================
# PHP / Composer Checker Logic
# ==============================================================================


def find_composer_files(path):
    """Finds composer.json and composer.lock in a directory."""
    manifest = None
    lock_file = None

    if os.path.exists(path):
        if os.path.isdir(path):
            candidates = os.listdir(path)
            if "composer.json" in candidates:
                manifest = os.path.join(path, "composer.json")
            if "composer.lock" in candidates:
                lock_file = os.path.join(path, "composer.lock")
        elif os.path.isfile(path):
            if path.endswith("composer.json"):
                manifest = path
                lock_dir = os.path.dirname(path)
                lock_cand = os.path.join(lock_dir, "composer.lock")
                if os.path.exists(lock_cand):
                    lock_file = lock_cand
            elif path.endswith("composer.lock"):
                lock_file = path
                json_dir = os.path.dirname(path)
                json_cand = os.path.join(json_dir, "composer.json")
                if os.path.exists(json_cand):
                    manifest = json_cand

    return manifest, lock_file


def parse_composer_json(filepath):
    """Parses composer.json for direct production and development dependencies."""
    dependencies = {}
    devDependencies = {}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        def filter_deps(deps_dict):
            filtered = {}
            for name, constraint in deps_dict.items():
                if "/" in name:
                    filtered[name] = constraint
            return filtered

        req = data.get("require", {})
        req_dev = data.get("require-dev", {})

        dependencies = filter_deps(req)
        devDependencies = filter_deps(req_dev)

    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning parsing composer.json: {e}{COLOR_RESET}"
        )

    return dependencies, devDependencies


def parse_composer_lock(filepath):
    """Parses composer.lock for resolved package versions and parent relationships."""
    resolved = {}
    parents = {}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        packages = data.get("packages", []) + data.get("packages-dev", [])

        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                clean_ver = version.lstrip("v")
                resolved.setdefault(name, set()).add(clean_ver)

                reqs = pkg.get("require", {})
                for child_name in reqs:
                    if "/" in child_name:
                        parents.setdefault(child_name, set()).add(name)

    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading composer.lock: {e}{COLOR_RESET}"
        )

    resolved_clean = {k: list(v) for k, v in resolved.items()}
    parents_clean = {k: list(v) for k, v in parents.items()}
    return resolved_clean, parents_clean


def check_composer_package(target):
    """Queries Packagist registry for composer package metadata."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    try:
        name_lower = name.lower()
        url = f"{URL_PACKAGIST_REGISTRY}{name_lower}.json"

        req = urllib.request.Request(url)
        with safe_urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        packages = data.get("packages", {})
        pkg_data = packages.get(name_lower, [])

        versions_list = []
        for item in pkg_data:
            v_str = item.get("version")
            if v_str:
                versions_list.append(v_str.lstrip("v"))

        stable_versions = []
        for v in versions_list:
            v_lower = v.lower()
            if not any(
                x in v_lower for x in ("-", "dev", "alpha", "beta", "rc", "patch")
            ) and RE_DECIMAL_VER_STRICT.match(v):
                stable_versions.append(v)

        valid_versions = stable_versions if stable_versions else versions_list

        for ver_str in versions_to_check:
            clean_ver = ver_str.lstrip("v") if ver_str else "0.0.0"
            if not clean_ver or clean_ver == "0.0.0":
                clean_ver = "0.0.0"

            latest_same_major, latest_absolute = find_latest_same_major(
                clean_ver, valid_versions
            )
            if not latest_same_major:
                latest_same_major = latest_absolute

            update_type = determine_update_type(
                clean_ver, latest_same_major, latest_absolute
            )

            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in {"major", "minor-major", "patch-major"}:
                raw_url = None
                for item in pkg_data:
                    v_str = item.get("version", "").lstrip("v")
                    if v_str == latest_absolute:
                        raw_url = item.get("source", {}).get("url") or item.get(
                            "homepage"
                        )
                        break
                if not raw_url and pkg_data:
                    raw_url = pkg_data[0].get("source", {}).get("url") or pkg_data[
                        0
                    ].get("homepage")
                repo_url = clean_repo_url(raw_url)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = (
                        f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    )

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": display_latest,
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": update_type,
                    "deprecated": None,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                }
            )

    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": error_msg,
                }
            )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": str(e),
                }
            )

    return results


def check_all_composer_targets(targets, max_workers):
    """Executes Packagist checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(
        targets,
        check_composer_package,
        f"{COLOR_GRAY}[Progress: Composer check]",
        max_workers,
    )


def run_composer_checker(args):
    """Main orchestrator for PHP / Composer checker."""
    manifest, lock_file = find_composer_files(args.path)

    if not manifest and not lock_file:
        print(
            f"{COLOR_RED}{ICON_ERROR} No composer.json or composer.lock found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    dependencies = {}
    devDependencies = {}
    if manifest:
        print(
            f"{COLOR_GRAY}{ICON_INFO} Reading composer.json dependencies...{COLOR_RESET}"
        )
        dependencies, devDependencies = parse_composer_json(manifest)

    lock_data = {}
    parents_data = {}
    if lock_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading composer.lock...{COLOR_RESET}")
        lock_data, parents_data = parse_composer_lock(lock_file)

    all_direct = {**dependencies, **devDependencies}
    targets = build_check_targets(
        {
            "dependencies": dependencies,
            "devDependencies": devDependencies,
            "all_direct": all_direct,
        },
        lock_data,
        args.all,
    )

    if not targets:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    results = check_all_composer_targets(targets, args.concurrent)

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["php"]
        osv_vulns = check_osv_vulnerabilities(
            targets, tech_info["osv_ecosystem"], args.concurrent
        )

        # Attach vulns back to results
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []

    # Resolve transitive dependency parents
    direct_packages = set(all_direct.keys())
    for r in results:
        direct_parents = find_direct_parents(r["name"], parents_data, direct_packages)
        r["required_by"] = sorted(direct_parents - {r["name"]})

    elapsed = time.time() - start_time

    return (
        results,
        {
            "dependencies": dependencies,
            "devDependencies": devDependencies,
            "all_direct": all_direct,
        },
        elapsed,
    )


# ==============================================================================
# Java / Maven Checker Logic
# ==============================================================================


def parse_maven_dependency_management(root, prefix, properties):
    """Parses dependencyManagement section to extract centrally managed versions."""
    dep_mgmt = {}
    dep_mgmt_elem = root.find(f"{prefix}dependencyManagement")
    if dep_mgmt_elem is not None:
        deps_elem = dep_mgmt_elem.find(f"{prefix}dependencies")
        if deps_elem is not None:
            for dep in deps_elem.findall(f"{prefix}dependency"):
                g_elem = dep.find(f"{prefix}groupId")
                a_elem = dep.find(f"{prefix}artifactId")
                v_elem = dep.find(f"{prefix}version")

                if g_elem is not None and a_elem is not None and v_elem is not None:
                    group = g_elem.text.strip() if g_elem.text else ""
                    artifact = a_elem.text.strip() if a_elem.text else ""
                    version = v_elem.text.strip() if v_elem.text else ""

                    # Interpolate properties
                    for prop_name, prop_val in properties.items():
                        group = group.replace(prop_name, prop_val)
                        artifact = artifact.replace(prop_name, prop_val)
                        version = version.replace(prop_name, prop_val)

                    if group and artifact and version:
                        dep_mgmt[f"{group}:{artifact}"] = version
    return dep_mgmt


def find_root_maven_pom(manifest_path):
    """Climbs parent pom.xml files via <relativePath> or parent directories to find top-level monorepo pom.xml."""
    curr = os.path.abspath(manifest_path)
    visited = set()
    root_pom = curr

    while curr and os.path.exists(curr) and curr not in visited:
        visited.add(curr)
        root_pom = curr
        try:
            tree = safe_et_parse(curr)
            root = tree.getroot()
            ns = root.tag.split("}")[0].lstrip("{") if "}" in root.tag else ""
            prefix = f"{{{ns}}}" if ns else ""

            parent_elem = root.find(f"{prefix}parent")
            if parent_elem is not None:
                rel_elem = parent_elem.find(f"{prefix}relativePath")
                rel_path = (
                    rel_elem.text.strip()
                    if (rel_elem is not None and rel_elem.text)
                    else "../pom.xml"
                )
                parent_pom_path = os.path.abspath(
                    os.path.join(os.path.dirname(curr), rel_path)
                )
                if os.path.exists(parent_pom_path):
                    curr = parent_pom_path
                    continue
            break
        except Exception:
            break

    return root_pom


def find_all_maven_poms(root_pom_path, base_dir=None, visited=None):
    """Recursively finds all module pom.xml files declared in a parent pom.xml."""
    if visited is None:
        visited = set()

    abs_root_pom = os.path.abspath(root_pom_path)
    root_dir = os.path.dirname(abs_root_pom)
    if base_dir is None:
        base_dir = root_dir

    poms = []
    if _is_safe_path(base_dir, abs_root_pom):
        if abs_root_pom in visited:
            return poms
        visited.add(abs_root_pom)
        poms.append(abs_root_pom)
    else:
        return poms

    try:
        if os.path.exists(abs_root_pom):
            tree = safe_et_parse(abs_root_pom)
            root = tree.getroot()

            ns = ""
            if "}" in root.tag:
                ns = root.tag.split("}")[0].lstrip("{")
            prefix = f"{{{ns}}}" if ns else ""

            modules_elem = root.find(f"{prefix}modules")
            if modules_elem is not None:
                for mod in modules_elem.findall(f"{prefix}module"):
                    if mod.text:
                        module_name = mod.text.strip()
                        module_path = module_name.replace("\\", "/")
                        module_pom = os.path.abspath(
                            os.path.join(root_dir, module_path, "pom.xml")
                        )
                        if _is_safe_path(base_dir, module_pom) and os.path.exists(
                            module_pom
                        ):
                            poms.extend(
                                find_all_maven_poms(
                                    module_pom, base_dir=base_dir, visited=visited
                                )
                            )
    except (OSError, ET.ParseError, ValueError):
        pass

    seen = set()
    unique_poms = []
    for p in poms:
        if p not in seen:
            seen.add(p)
            unique_poms.append(p)

    return unique_poms


def parse_maven_pom_recursive(
    filepath, parent_dep_mgmt=None, seen_files=None, base_dir=None
):
    """Parses Maven pom.xml recursively, resolving parent project properties and dependencyManagement."""
    if seen_files is None:
        seen_files = set()

    abs_path = os.path.abspath(filepath)
    if base_dir is None:
        base_dir = os.path.dirname(abs_path)

    if not _is_safe_path(base_dir, abs_path):
        return {}, {}, {}

    if abs_path in seen_files:
        return {}, {}, {}

    seen_files.add(abs_path)

    dependencies = {}
    properties = {}
    dep_mgmt = {}

    if parent_dep_mgmt is not None:
        dep_mgmt.update(parent_dep_mgmt)

    try:
        if _is_safe_path(base_dir, abs_path) and os.path.exists(abs_path):
            tree = safe_et_parse(abs_path)
            root = tree.getroot()

            ns = ""
            if "}" in root.tag:
                ns = root.tag.split("}")[0].lstrip("{")
            prefix = f"{{{ns}}}" if ns else ""

            # 1. Resolve parent POM first if declared
            parent_elem = root.find(f"{prefix}parent")
            if parent_elem is not None:
                rel_path_elem = parent_elem.find(f"{prefix}relativePath")
                rel_path = (
                    rel_path_elem.text.strip()
                    if (rel_path_elem is not None and rel_path_elem.text)
                    else "../pom.xml"
                )
                parent_pom_path = os.path.abspath(
                    os.path.join(os.path.dirname(abs_path), rel_path)
                )
                if os.path.exists(parent_pom_path):
                    parent_dir = os.path.dirname(parent_pom_path)
                    _p_deps, p_props, p_dep_mgmt = parse_maven_pom_recursive(
                        parent_pom_path,
                        parent_dep_mgmt,
                        seen_files,
                        base_dir=parent_dir,
                    )
                    properties.update(p_props)
                    dep_mgmt.update(p_dep_mgmt)

            # 2. Parse local properties
            props_elem = root.find(f"{prefix}properties")
            if props_elem is not None:
                for elem in props_elem:
                    tag_local = elem.tag.split("}")[-1]
                    properties[f"${{{tag_local}}}"] = (elem.text or "").strip()

            properties["${project.version}"] = (
                root.findtext(f"{prefix}version") or ""
            ).strip()
            properties["${project.groupId}"] = (
                root.findtext(f"{prefix}groupId") or ""
            ).strip()

            if parent_elem is not None:
                if not properties["${project.version}"]:
                    properties["${project.version}"] = (
                        parent_elem.findtext(f"{prefix}version") or ""
                    ).strip()
                if not properties["${project.groupId}"]:
                    properties["${project.groupId}"] = (
                        parent_elem.findtext(f"{prefix}groupId") or ""
                    ).strip()

            # Interpolate properties recursively in properties dictionary
            for _ in range(5):
                prop_changed = False
                for p_k, p_v in list(properties.items()):
                    if p_v and "${" in p_v:
                        for sub_k, sub_v in properties.items():
                            if sub_v and sub_k in p_v:
                                properties[p_k] = p_v.replace(sub_k, sub_v)
                                prop_changed = True
                if not prop_changed:
                    break

            # 3. Parse local dependencyManagement
            local_dep_mgmt = parse_maven_dependency_management(root, prefix, properties)
            dep_mgmt.update(local_dep_mgmt)

            # 4. Parse active dependencies
            deps_elem = root.find(f"{prefix}dependencies")
            if deps_elem is not None:
                for dep in deps_elem.findall(f"{prefix}dependency"):
                    g_elem = dep.find(f"{prefix}groupId")
                    a_elem = dep.find(f"{prefix}artifactId")
                    v_elem = dep.find(f"{prefix}version")

                    if g_elem is not None and a_elem is not None:
                        group = g_elem.text.strip() if g_elem.text else ""
                        artifact = a_elem.text.strip() if a_elem.text else ""

                        for _ in range(5):
                            changed = False
                            for prop_name, prop_val in properties.items():
                                if prop_val:
                                    if prop_name in group:
                                        group = group.replace(prop_name, prop_val)
                                        changed = True
                                    if prop_name in artifact:
                                        artifact = artifact.replace(prop_name, prop_val)
                                        changed = True
                            if not changed:
                                break

                        if group and artifact:
                            coord = f"{group}:{artifact}"
                            version = "*"
                            if v_elem is not None and v_elem.text:
                                version = v_elem.text.strip()
                            elif coord in dep_mgmt:
                                version = dep_mgmt[coord]

                            for _ in range(5):
                                changed = False
                                for prop_name, prop_val in properties.items():
                                    if prop_val and prop_name in version:
                                        version = version.replace(prop_name, prop_val)
                                        changed = True
                                if not changed:
                                    break

                            if "${" in version:
                                print(
                                    f"{COLOR_YELLOW}{ICON_WARN} Unresolved version property '{version}' for Maven package '{coord}' in {os.path.basename(filepath)}{COLOR_RESET}"
                                )

                            dependencies[coord] = version

    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing pom.xml: {e}{COLOR_RESET}")

    return dependencies, properties, dep_mgmt


def parse_maven_pom(filepath, parent_dep_mgmt=None, base_dir=None):
    """Parses Maven pom.xml for direct dependencies, resolving parent properties and dependencyManagement."""
    deps, _, _ = parse_maven_pom_recursive(filepath, parent_dep_mgmt, base_dir=base_dir)
    return deps


_MAVEN_REMOTE_POM_CACHE = {}


def fetch_remote_maven_pom(group_id, artifact_id, version, custom_registries=None):
    """Fetches and parses a .pom XML file for a Maven artifact from remote registries."""
    if not group_id or not artifact_id or not version or version == "*":
        return None
    cache_key = (group_id, artifact_id, version)
    if cache_key in _MAVEN_REMOTE_POM_CACHE:
        return _MAVEN_REMOTE_POM_CACHE[cache_key]

    group_path = group_id.replace(".", "/")
    use_google_maven = (
        group_id.startswith(
            ("androidx.", "com.google.android.", "com.android.", "android.arch.")
        )
        or "android" in group_id
    )
    base_registries = (
        [URL_GOOGLE_MAVEN, URL_MAVEN_REGISTRY]
        if use_google_maven
        else [URL_MAVEN_REGISTRY, URL_GOOGLE_MAVEN]
    )
    registries = []
    if custom_registries:
        for r in custom_registries:
            if r not in registries:
                registries.append(r)
    for r in base_registries:
        if r not in registries:
            registries.append(r)

    root = None
    for registry_url in registries:
        url = f"{registry_url}{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
        try:
            root = _fetch_registry_json_or_xml(url, format="xml")
            if root is not None:
                break
        except (urllib.error.URLError, OSError, ET.ParseError, TimeoutError):
            continue

    _MAVEN_REMOTE_POM_CACHE[cache_key] = root
    return root


def resolve_maven_transitive_dependencies(
    direct_deps, max_depth=3, max_workers=10, custom_registries=None
):
    """
    Recursively fetches remote .pom files for Maven dependencies to extract transitive dependencies
    and build required_by parent relationships.
    """
    all_deps = dict(direct_deps)
    required_by_map = {coord: set() for coord in direct_deps}
    dep_types = {coord: "Direct" for coord in direct_deps}
    visited = set()

    current_level = []
    for coord, ver in direct_deps.items():
        if ":" in coord and ver and ver != "*":
            current_level.append((coord, ver))

    depth = 0
    while current_level and depth < max_depth:
        next_level_items = []

        def _process_item(item):
            parent_coord, version = item
            if (parent_coord, version) in visited:
                return []
            visited.add((parent_coord, version))

            if ":" not in parent_coord:
                return []

            group_id, artifact_id = parent_coord.split(":", 1)
            pom_root = fetch_remote_maven_pom(
                group_id, artifact_id, version, custom_registries=custom_registries
            )
            if pom_root is None:
                return []

            ns = ""
            if "}" in pom_root.tag:
                ns = pom_root.tag.split("}")[0].lstrip("{")
            prefix = f"{{{ns}}}" if ns else ""

            # Extract local properties for interpolation
            properties = {}
            props_elem = pom_root.find(f"{prefix}properties")
            if props_elem is not None:
                for elem in props_elem:
                    tag_local = elem.tag.split("}")[-1]
                    properties[f"${{{tag_local}}}"] = (elem.text or "").strip()

            properties["${project.version}"] = version
            properties["${project.groupId}"] = group_id
            properties["${pom.version}"] = version

            parent_dep_mgmt = {}
            parent_elem = pom_root.find(f"{prefix}parent")
            if parent_elem is not None:
                p_group = parent_elem.findtext(f"{prefix}groupId") or ""
                p_artifact = parent_elem.findtext(f"{prefix}artifactId") or ""
                p_version = parent_elem.findtext(f"{prefix}version") or ""
                p_group, p_artifact, p_version = (
                    p_group.strip(),
                    p_artifact.strip(),
                    p_version.strip(),
                )
                if p_group and p_artifact and p_version:
                    parent_pom_root = fetch_remote_maven_pom(
                        p_group,
                        p_artifact,
                        p_version,
                        custom_registries=custom_registries,
                    )
                    if parent_pom_root is not None:
                        p_ns = (
                            parent_pom_root.tag.split("}")[0].lstrip("{")
                            if "}" in parent_pom_root.tag
                            else ""
                        )
                        p_prefix = f"{{{p_ns}}}" if p_ns else ""
                        p_props_elem = parent_pom_root.find(f"{p_prefix}properties")
                        if p_props_elem is not None:
                            for elem in p_props_elem:
                                tag_local = elem.tag.split("}")[-1]
                                properties[f"${{{tag_local}}}"] = (
                                    elem.text or ""
                                ).strip()
                        parent_dep_mgmt = parse_maven_dependency_management(
                            parent_pom_root, p_prefix, properties
                        )

            local_dep_mgmt = parse_maven_dependency_management(
                pom_root, prefix, properties
            )
            parent_dep_mgmt.update(local_dep_mgmt)

            deps_elem = pom_root.find(f"{prefix}dependencies")
            extracted = []
            if deps_elem is not None:
                for dep in deps_elem.findall(f"{prefix}dependency"):
                    g_elem = dep.find(f"{prefix}groupId")
                    a_elem = dep.find(f"{prefix}artifactId")
                    v_elem = dep.find(f"{prefix}version")
                    s_elem = dep.find(f"{prefix}scope")
                    opt_elem = dep.find(f"{prefix}optional")

                    scope = (
                        s_elem.text.strip()
                        if (s_elem is not None and s_elem.text)
                        else "compile"
                    ).lower()
                    if scope in {"test", "provided", "system"}:
                        continue

                    if (
                        opt_elem is not None
                        and opt_elem.text
                        and opt_elem.text.strip().lower() == "true"
                    ):
                        continue

                    if g_elem is not None and a_elem is not None:
                        c_group = g_elem.text.strip() if g_elem.text else ""
                        c_artifact = a_elem.text.strip() if a_elem.text else ""
                        c_version = (
                            v_elem.text.strip()
                            if (v_elem is not None and v_elem.text)
                            else "*"
                        )

                        for prop_k, prop_v in properties.items():
                            if prop_v:
                                c_group = c_group.replace(prop_k, prop_v)
                                c_artifact = c_artifact.replace(prop_k, prop_v)
                                c_version = c_version.replace(prop_k, prop_v)

                        c_coord = f"{c_group}:{c_artifact}"
                        if (
                            c_version == "*" or c_version.startswith("${")
                        ) and c_coord in parent_dep_mgmt:
                            c_version = parent_dep_mgmt[c_coord]

                        if c_group and c_artifact and not c_version.startswith("${"):
                            extracted.append((parent_coord, c_coord, c_version))

            return extracted

        workers = min(max_workers, max(1, len(current_level)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results_lists = list(executor.map(_process_item, current_level))

        for item_results in results_lists:
            for parent_coord, child_coord, child_version in item_results:
                if child_coord not in required_by_map:
                    required_by_map[child_coord] = set()
                required_by_map[child_coord].add(parent_coord)

                if child_coord not in all_deps:
                    all_deps[child_coord] = child_version
                    dep_types[child_coord] = "Transitive"
                    if child_version and child_version != "*":
                        next_level_items.append((child_coord, child_version))

        current_level = next_level_items
        depth += 1

    return all_deps, required_by_map, dep_types


def check_maven_package(target):
    """Queries Maven Central Repository for package metadata."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]
    custom_registries = target.get("custom_registries", [])

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    try:
        if ":" not in name:
            raise ValueError(f"Invalid Maven coordinate structure: {name}")

        group_id, artifact_id = name.split(":", 1)
        group_path = group_id.replace(".", "/")
        use_google_maven = (
            group_id.startswith(
                ("androidx.", "com.google.android.", "com.android.", "android.arch.")
            )
            or "android" in group_id
        )

        xml_data = None
        base_registries = (
            [URL_GOOGLE_MAVEN, URL_MAVEN_REGISTRY]
            if use_google_maven
            else [URL_MAVEN_REGISTRY, URL_GOOGLE_MAVEN]
        )
        registries = []
        if custom_registries:
            for r in custom_registries:
                if r not in registries:
                    registries.append(r)
        for r in base_registries:
            if r not in registries:
                registries.append(r)

        last_error = None
        successful_registry = URL_MAVEN_REGISTRY
        for registry_url in registries:
            url = f"{registry_url}{group_path}/{artifact_id}/maven-metadata.xml"
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", f"Kevlar-CheckDeps/{VERSION}")
                with safe_urlopen(req, timeout=10) as response:
                    xml_data = response.read()
                successful_registry = registry_url
                break
            except Exception as e:
                last_error = e
                continue

        versions_list = []
        if xml_data is not None:
            root = safe_et_fromstring(xml_data)
            versioning_elem = root.find("versioning")
            if versioning_elem is not None:
                versions_elem = versioning_elem.find("versions")
                if versions_elem is not None:
                    for v in versions_elem.findall("version"):
                        if v.text:
                            versions_list.append(v.text.strip())
        else:
            # Fallback to search.maven.org API for legacy packages lacking maven-metadata.xml
            try:
                solr_url = f"https://search.maven.org/solrsearch/select?q=g:%22{group_id}%22+AND+a:%22{artifact_id}%22&wt=json"
                req = urllib.request.Request(solr_url)
                req.add_header("User-Agent", f"Kevlar-CheckDeps/{VERSION}")
                with safe_urlopen(req, timeout=10) as response:
                    solr_data = json.loads(response.read().decode("utf-8"))
                docs = solr_data.get("response", {}).get("docs", [])
                for doc in docs:
                    v_val = doc.get("v") or doc.get("latestVersion")
                    if v_val:
                        versions_list.append(str(v_val))
            except Exception as solr_err:
                last_error = solr_err

        if not versions_list:
            raise ValueError(
                f"Failed to fetch metadata from Maven or Google registries: {last_error or 'Not found'}"
            )

        stable_versions = []
        for v in versions_list:
            v_lower = v.lower()
            is_prerelease = False
            if "snapshot" in v_lower:
                is_prerelease = True
            else:
                m = RE_MAVEN_PRERELEASE.search(v_lower)
                if m:
                    is_prerelease = True
            if not is_prerelease:
                stable_versions.append(v)

        valid_versions = stable_versions if stable_versions else versions_list

        for ver_str in versions_to_check:
            clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"

            latest_same_major, latest_absolute = find_latest_same_major(
                clean_ver, valid_versions
            )
            if not latest_same_major:
                latest_same_major = latest_absolute

            update_type = determine_update_type(
                clean_ver, latest_same_major, latest_absolute
            )

            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in {"major", "minor-major", "patch-major"}:
                repo_url = resolve_maven_repo(
                    successful_registry, group_path, artifact_id, latest_absolute
                )
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = (
                        f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    )

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": display_latest,
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": update_type,
                    "deprecated": None,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                }
            )

    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": error_msg,
                }
            )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": str(e),
                }
            )

    return results


def check_all_maven_targets(targets, max_workers):
    """Executes Maven Repository checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(
        targets,
        check_maven_package,
        f"{COLOR_GRAY}[Progress: Maven check]",
        max_workers,
    )


def run_maven_checker(args):
    """Main orchestrator for Maven dependency checker, supporting multi-module poms recursively."""
    manifest = None
    if os.path.exists(args.path):
        if os.path.isdir(args.path):
            cand = os.path.join(args.path, "pom.xml")
            if os.path.exists(cand):
                manifest = cand
        elif os.path.isfile(args.path) and args.path.endswith("pom.xml"):
            manifest = args.path

    if not manifest:
        print(f"{COLOR_RED}{ICON_ERROR} No pom.xml found in: {args.path}{COLOR_RESET}")
        return None, None, 0

    manifest_dir = os.path.dirname(os.path.abspath(manifest))
    print(f"{COLOR_GRAY}{ICON_INFO} Resolving Maven module tree...{COLOR_RESET}")
    root_manifest = find_root_maven_pom(manifest)
    root_manifest_dir = os.path.dirname(os.path.abspath(root_manifest))
    all_poms = find_all_maven_poms(root_manifest, base_dir=root_manifest_dir)
    if os.path.abspath(manifest) not in [os.path.abspath(p) for p in all_poms]:
        all_poms.append(os.path.abspath(manifest))

    if len(all_poms) > 1:
        print(
            f"{COLOR_GRAY}{ICON_INFO} Multi-module project detected. Found {len(all_poms)} modules.{COLOR_RESET}"
        )

    # 1. Parse root pom.xml for centralized dependencyManagement versions
    root_dep_mgmt = {}
    try:
        if _is_safe_path(manifest_dir, manifest) and os.path.exists(manifest):
            tree = safe_et_parse(manifest)
            root = tree.getroot()
            ns = root.tag.split("}")[0].lstrip("{") if "}" in root.tag else ""
            prefix = f"{{{ns}}}" if ns else ""

            # Base properties for root dependencyManagement
            properties = {}
            props_elem = root.find(f"{prefix}properties")
            if props_elem is not None:
                for elem in props_elem:
                    tag_local = elem.tag.split("}")[-1]
                    properties[f"${{{tag_local}}}"] = (elem.text or "").strip()

            properties["${project.version}"] = (
                root.findtext(f"{prefix}version") or ""
            ).strip()
            properties["${project.groupId}"] = (
                root.findtext(f"{prefix}groupId") or ""
            ).strip()

            root_dep_mgmt = parse_maven_dependency_management(root, prefix, properties)
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading root dependencyManagement: {e}{COLOR_RESET}"
        )

    # 2. Extract local monorepo module coordinates, project groupIds, and custom repositories
    local_modules = set()
    local_group_ids = set()
    custom_registries = []

    for pom_path in all_poms:
        try:
            tree = safe_et_parse(pom_path)
            root_elem = tree.getroot()
            m_ns = (
                root_elem.tag.split("}")[0].lstrip("{") if "}" in root_elem.tag else ""
            )
            m_prefix = f"{{{m_ns}}}" if m_ns else ""

            g_elem = root_elem.find(f"{m_prefix}groupId")
            if g_elem is None or not g_elem.text:
                parent_elem = root_elem.find(f"{m_prefix}parent")
                if parent_elem is not None:
                    g_elem = parent_elem.find(f"{m_prefix}groupId")
            a_elem = root_elem.find(f"{m_prefix}artifactId")

            group = g_elem.text.strip() if (g_elem is not None and g_elem.text) else ""
            artifact = (
                a_elem.text.strip() if (a_elem is not None and a_elem.text) else ""
            )
            if group:
                local_group_ids.add(group)
            if group and artifact:
                local_modules.add(f"{group}:{artifact}")

            repos_elem = root_elem.find(f"{m_prefix}repositories")
            if repos_elem is not None:
                for repo in repos_elem.findall(f"{m_prefix}repository"):
                    url_elem = repo.find(f"{m_prefix}url")
                    if url_elem is not None and url_elem.text:
                        u = url_elem.text.strip()
                        if not u.endswith("/"):
                            u += "/"
                        if (
                            u.startswith(("http://", "https://"))
                            and u not in custom_registries
                        ):
                            custom_registries.append(u)
        except (OSError, ET.ParseError, ValueError):
            pass

    # 3. Parse all module poms and merge active dependencies
    pkg_data = {}
    print(f"{COLOR_GRAY}{ICON_INFO} Reading Maven pom.xml modules...{COLOR_RESET}")
    for pom in all_poms:
        pom_deps = parse_maven_pom(pom, root_dep_mgmt, base_dir=manifest_dir)
        pkg_data.update(pom_deps)

    direct_deps = dict(pkg_data)

    # 4. Resolve transitive dependencies via remote POM resolution
    print(
        f"{COLOR_GRAY}{ICON_INFO} Resolving Maven transitive dependency tree...{COLOR_RESET}"
    )
    all_deps, required_by_map, dep_types = resolve_maven_transitive_dependencies(
        direct_deps,
        max_depth=3,
        max_workers=getattr(args, "concurrent", 10),
        custom_registries=custom_registries,
    )

    remote_targets = []
    local_results = []

    for name, version in all_deps.items():
        is_direct = name in direct_deps
        if not getattr(args, "all", True) and not is_direct:
            continue
        declared_ver = direct_deps.get(name, "Transitive")
        installed_ver = version if version != "*" else (direct_deps.get(name) or "*")

        g_id = name.split(":", 1)[0] if ":" in name else ""
        is_internal_module = (name in local_modules) or (
            g_id and g_id in local_group_ids
        )

        if is_internal_module:
            local_results.append(
                {
                    "name": name,
                    "declared": declared_ver,
                    "installed": installed_ver,
                    "latest": installed_ver,
                    "latest_same_major": installed_ver,
                    "latest_absolute": installed_ver,
                    "status": "local",
                    "deprecated": None,
                    "error": None,
                    "repo_url": None,
                    "compare_url": None,
                    "releases_url": None,
                }
            )
        else:
            remote_targets.append(
                {
                    "name": name,
                    "declared": declared_ver,
                    "installed": [installed_ver] if installed_ver != "*" else [],
                    "custom_registries": custom_registries,
                }
            )

    if not remote_targets and not local_results:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    results = (
        check_all_maven_targets(remote_targets, args.concurrent)
        if remote_targets
        else []
    )
    results.extend(local_results)

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False) and remote_targets:
        tech_info = TECHNOLOGIES["maven"]
        osv_vulns = check_osv_vulnerabilities(
            remote_targets, tech_info["osv_ecosystem"], args.concurrent
        )

        for r in results:
            if r["status"] != "local":
                key = (r["name"], r["installed"])
                r["vulnerabilities"] = osv_vulns.get(key, [])
            else:
                r["vulnerabilities"] = []
    else:
        for r in results:
            r["vulnerabilities"] = []

    for r in results:
        name = r["name"]
        parents = sorted(required_by_map.get(name, set()))
        r["required_by"] = parents
        r["dep_type"] = dep_types.get(name, "Transitive" if parents else "Direct")

    elapsed = time.time() - start_time

    return (
        results,
        {"dependencies": all_deps, "devDependencies": {}, "all_direct": direct_deps},
        elapsed,
    )


# ==============================================================================
# Go Modules Checker Logic
# ==============================================================================


def escape_go_module(name):
    """Encodes uppercase characters in Go module paths using the ! scheme."""
    escaped = ""
    for char in name:
        if char.isupper():
            escaped += "!" + char.lower()
        else:
            escaped += char
    return escaped


def parse_go_work(filepath):
    """Parses go.work workspace files for module directories in 'use' blocks/directives."""
    modules = []
    if not filepath or not os.path.exists(filepath):
        return modules
    try:
        base_dir = os.path.dirname(filepath)
        in_use_block = False
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line_clean = line.strip()
                if not line_clean or line_clean.startswith("//"):
                    continue
                if line_clean.startswith("use") and line_clean.endswith("("):
                    in_use_block = True
                    continue
                elif in_use_block and line_clean == ")":
                    in_use_block = False
                    continue

                parts = line_clean.split()
                if in_use_block:
                    rel_path = parts[0]
                    mod_path = os.path.abspath(
                        os.path.join(base_dir, rel_path, "go.mod")
                    )
                    if os.path.exists(mod_path):
                        modules.append(mod_path)
                elif line_clean.startswith("use "):
                    if len(parts) >= 2:
                        rel_path = parts[1]
                        mod_path = os.path.abspath(
                            os.path.join(base_dir, rel_path, "go.mod")
                        )
                        if os.path.exists(mod_path):
                            modules.append(mod_path)
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing go.work: {e}{COLOR_RESET}")
    return modules


def parse_go_mod(filepath):
    """Parses go.mod for direct, indirect, tools, replacements, excludes, and retractions."""
    dependencies = {}
    devDependencies = {}
    local_replacements = {}
    excluded_versions = {}
    retracted_versions = {}

    if not filepath or not os.path.exists(filepath):
        return (
            dependencies,
            devDependencies,
            local_replacements,
            excluded_versions,
            retracted_versions,
        )

    raw_reqs = []
    replacements = {}
    replacements_ver = {}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_require_block = False
        in_exclude_block = False
        in_retract_block = False
        in_tool_block = False

        for line in lines:
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("//"):
                continue

            is_indirect = False
            if "//" in line_clean:
                parts = line_clean.split("//", 1)
                line_content = parts[0].strip()
                comment = parts[1].strip()
                if "indirect" in comment.split():
                    is_indirect = True
            else:
                line_content = line_clean

            if not line_content:
                continue

            if line_content.startswith("require") and line_content.endswith("("):
                in_require_block = True
                continue
            elif in_require_block and line_content == ")":
                in_require_block = False
                continue

            if line_content.startswith("exclude") and line_content.endswith("("):
                in_exclude_block = True
                continue
            elif in_exclude_block and line_content == ")":
                in_exclude_block = False
                continue

            if line_content.startswith("retract") and line_content.endswith("("):
                in_retract_block = True
                continue
            elif in_retract_block and line_content == ")":
                in_retract_block = False
                continue

            if line_content.startswith("tool") and line_content.endswith("("):
                in_tool_block = True
                continue
            elif in_tool_block and line_content == ")":
                in_tool_block = False
                continue

            if "=>" in line_content:
                left, right = line_content.split("=>", 1)
                left_parts = left.strip().split()
                if left_parts and left_parts[0] == "replace":
                    left_parts = left_parts[1:]

                right_parts = right.strip().split()
                left_pkg = left_parts[0] if left_parts else None
                left_ver = left_parts[1] if len(left_parts) >= 2 else None

                if left_pkg and right_parts:
                    target_path = right_parts[0]
                    is_local_path = (
                        target_path.startswith((".", "/", "\\")) or len(right_parts) == 1
                    )
                    if is_local_path:
                        local_replacements[left_pkg] = target_path
                    elif len(right_parts) >= 2:
                        new_path, new_version = right_parts[0], right_parts[1]
                        if left_ver:
                            replacements_ver[(left_pkg, left_ver)] = (
                                new_path,
                                new_version,
                            )
                        else:
                            replacements[left_pkg] = (new_path, new_version)
                continue

            if in_exclude_block or line_content.startswith("exclude"):
                parts = line_content.split()
                if line_content.startswith("exclude"):
                    parts = parts[1:]
                if len(parts) >= 2:
                    ex_pkg, ex_ver = parts[0], parts[1]
                    excluded_versions.setdefault(ex_pkg, set()).add(ex_ver)
                continue

            if in_retract_block or line_content.startswith("retract"):
                parts = line_content.split()
                if line_content.startswith("retract"):
                    parts = parts[1:]
                if len(parts) >= 1:
                    ret_ver = parts[0].strip("[]()")
                    retracted_versions.setdefault("_global", set()).add(ret_ver)
                continue

            if in_tool_block or line_content.startswith("tool"):
                parts = line_content.split()
                if line_content.startswith("tool"):
                    parts = parts[1:]
                if parts:
                    tool_pkg = parts[0]
                    devDependencies[tool_pkg] = "tool"
                continue

            if in_require_block:
                req_parts = line_content.split()
                if len(req_parts) >= 2:
                    pkg = req_parts[0]
                    ver = req_parts[1]
                    raw_reqs.append((pkg, ver, is_indirect))
            else:
                if line_content.startswith("require"):
                    req_parts = line_content.split()
                    if len(req_parts) >= 3:
                        pkg = req_parts[1]
                        ver = req_parts[2]
                        raw_reqs.append((pkg, ver, is_indirect))

        for pkg, ver, is_indir in raw_reqs:
            final_pkg = pkg
            final_ver = ver

            if (pkg, ver) in replacements_ver:
                final_pkg, final_ver = replacements_ver[(pkg, ver)]
            elif pkg in replacements:
                final_pkg, final_ver = replacements[pkg]

            if is_indir:
                devDependencies[final_pkg] = final_ver
            else:
                dependencies[final_pkg] = final_ver

    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing go.mod: {e}{COLOR_RESET}")

    return (
        dependencies,
        devDependencies,
        local_replacements,
        excluded_versions,
        retracted_versions,
    )


def check_go_package(target):
    """Queries proxy.golang.org for Go module versions list."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]
    excluded_set = target.get("excluded_versions") or set()
    retracted_set = target.get("retracted_versions") or set()

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    try:
        candidate_name = name
        resp_data = None

        while True:
            try:
                escaped_name = escape_go_module(candidate_name)
                url = f"{URL_GO_PROXY}{escaped_name}/@v/list"
                req = urllib.request.Request(url)
                with safe_urlopen(req, timeout=10) as response:
                    resp_data = response.read().decode("utf-8")
                break
            except urllib.error.HTTPError as err:
                if err.code == 404 and "/" in candidate_name:
                    candidate_name = candidate_name.rsplit("/", 1)[0]
                else:
                    raise

        versions_list = [v.strip() for v in resp_data.split("\n") if v.strip()]

        stable_versions = []
        for v in versions_list:
            v_lower = v.lower()
            if not any(x in v_lower for x in ("-", "alpha", "beta", "rc", "dev")):
                clean_v = v.split("+")[0]
                stable_versions.append((v, clean_v))

        valid_versions = (
            stable_versions
            if stable_versions
            else [(v, v.split("+")[0]) for v in versions_list]
        )

        # Exclude versions specified in exclude / retract directives
        if excluded_set or retracted_set:
            filtered = [
                item
                for item in valid_versions
                if item[0] not in excluded_set and item[0] not in retracted_set
            ]
            if filtered:
                valid_versions = filtered

        all_versions = [item[0] for item in valid_versions]

        for ver_str in versions_to_check:
            latest_same_major, latest_absolute = find_latest_same_major(
                ver_str, all_versions
            )
            if not latest_same_major:
                latest_same_major = latest_absolute

            clean_ver = ver_str.lstrip("v").split("+")[0] if ver_str else ""
            (
                latest_absolute.lstrip("v").split("+")[0] if latest_absolute else ""
            )
            (
                latest_same_major.lstrip("v").split("+")[0] if latest_same_major else ""
            )
            update_type = determine_update_type(
                ver_str, latest_same_major, latest_absolute
            )

            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in {"major", "minor-major", "patch-major"}:
                repo_url = resolve_go_repo(name)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = (
                        f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    )

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": display_latest,
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": update_type,
                    "deprecated": None,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                    "dep_type": target.get("dep_type", "Direct"),
                }
            )

    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": error_msg,
                    "dep_type": target.get("dep_type", "Direct"),
                }
            )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": str(e),
                    "dep_type": target.get("dep_type", "Direct"),
                }
            )

    return results


def check_all_go_targets(targets, max_workers):
    """Executes Go modules checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(
        targets, check_go_package, f"{COLOR_GRAY}[Progress: Go check]", max_workers
    )


def resolve_go_parent_graph(direct_deps, max_workers=10):
    """
    Fetches .mod files for direct Go dependencies via GOPROXY concurrently
    to map which direct dependencies require each transitive dependency.
    Returns dict: { child_package_name: set([parent_package_name, ...]) }
    """
    parents = {}
    if not direct_deps:
        return parents

    total = len(direct_deps)
    completed = 0
    lock = threading.Lock()

    def _fetch_single_mod(item):
        nonlocal completed
        name, ver = item
        if name and ver:
            try:
                esc = escape_go_module(name)
                url = f"{URL_GO_PROXY}{esc}/@v/{ver}.mod"
                req = urllib.request.Request(url)
                with safe_urlopen(req, timeout=6) as response:
                    mod_text = response.read().decode("utf-8")

                in_require_block = False
                for line in mod_text.splitlines():
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith("//"):
                        continue
                    if line_clean.startswith("require") and line_clean.endswith("("):
                        in_require_block = True
                        continue
                    elif in_require_block and line_clean == ")":
                        in_require_block = False
                        continue

                    line_content = (
                        line_clean.split("//", 1)[0].strip()
                        if "//" in line_clean
                        else line_clean
                    )
                    if not line_content:
                        continue

                    parts = line_content.split()
                    if in_require_block and len(parts) >= 2:
                        child_pkg = parts[0]
                        parents.setdefault(child_pkg, set()).add(name)
                    elif (
                        not in_require_block
                        and line_content.startswith("require")
                        and len(parts) >= 3
                    ):
                        child_pkg = parts[1]
                        parents.setdefault(child_pkg, set()).add(name)
            except (OSError, UnicodeDecodeError, IndexError):
                pass

        with lock:
            completed += 1
            pct = int((completed / total) * 100)
            sys.stdout.write(
                f"\r{COLOR_GRAY}{ICON_INFO} Resolving parent dependency graph for Go modules: {completed}/{total} ({pct}%)...{COLOR_RESET}"
            )
            sys.stdout.flush()

    sys.stdout.write(
        f"{COLOR_GRAY}{ICON_INFO} Resolving parent dependency graph for Go modules: 0/{total} (0%)...{COLOR_RESET}"
    )
    sys.stdout.flush()

    with ThreadPoolExecutor(max_workers=min(max_workers, 15)) as executor:
        executor.map(_fetch_single_mod, direct_deps.items())

    sys.stdout.write("\n")
    sys.stdout.flush()
    return parents


def parse_go_sum(filepath):
    """Parses go.sum file into dict mapping (module, version) -> h1_hash."""
    checksums = {}
    if not filepath or not os.path.exists(filepath):
        return checksums
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line_clean = line.strip()
                if not line_clean or line_clean.startswith("//"):
                    continue
                parts = line_clean.split()
                if len(parts) >= 3:
                    mod_name = parts[0]
                    ver_str = parts[1]
                    hash_str = parts[2]
                    if not ver_str.endswith("/go.mod") and hash_str.startswith("h1:"):
                        checksums[(mod_name, ver_str)] = hash_str
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing go.sum: {e}{COLOR_RESET}")
    return checksums


def verify_go_checksums(results, go_sum_path, max_workers=10):
    """Verifies local go.sum entries against sum.golang.org Checksum Database."""
    has_sum_file = (
        os.path.exists(go_sum_path)
        if (go_sum_path and os.path.exists(go_sum_path))
        else False
    )
    local_checksums = parse_go_sum(go_sum_path) if has_sum_file else {}

    if not has_sum_file:
        for r in results:
            if r.get("status") != "local":
                r["missing_checksum"] = True
        return

    items_to_verify = []
    for r in results:
        if r.get("status") == "local":
            continue
        name = r["name"]
        installed = r.get("installed") or r.get("declared")
        if isinstance(installed, list):
            installed = installed[0] if installed else None

        if not installed:
            continue

        key = (name, installed)
        if key not in local_checksums:
            r["missing_checksum"] = True
        else:
            items_to_verify.append((r, name, installed, local_checksums[key]))

    total = len(items_to_verify)
    if total == 0:
        return

    completed = 0
    lock = threading.Lock()

    def _verify_single(item):
        nonlocal completed
        r, name, ver, local_hash = item
        try:
            esc = escape_go_module(name)
            url = f"https://sum.golang.org/lookup/{esc}@{ver}"
            req = urllib.request.Request(url)
            with safe_urlopen(req, timeout=6) as response:
                resp_text = response.read().decode("utf-8")

            official_hash = None
            prefix = f"{name} {ver} h1:"
            for line in resp_text.splitlines():
                if line.startswith(prefix):
                    official_hash = line.split(prefix, 1)[1].strip()
                    break

            if official_hash and (
                f"h1:{official_hash}" != local_hash and official_hash != local_hash
            ):
                r["mismatch_checksum"] = True
            elif official_hash:
                r["checksum_verified"] = True
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            pass

        with lock:
            completed += 1
            pct = int((completed / total) * 100)
            sys.stdout.write(
                f"\r{COLOR_GRAY}{ICON_INFO} Verifying go.sum checksums against sum.golang.org: {completed}/{total} ({pct}%)...{COLOR_RESET}"
            )
            sys.stdout.flush()

    sys.stdout.write(
        f"{COLOR_GRAY}{ICON_INFO} Verifying go.sum checksums against sum.golang.org: 0/{total} (0%)...{COLOR_RESET}"
    )
    sys.stdout.flush()

    with ThreadPoolExecutor(max_workers=min(max_workers, 15)) as executor:
        executor.map(_verify_single, items_to_verify)

    sys.stdout.write("\n")
    sys.stdout.flush()


def run_go_checker(args):
    """Main orchestrator for Go Modules checker with workspace (go.work) and local replace support."""
    manifests = []
    if os.path.exists(args.path):
        if os.path.isdir(args.path):
            work_file = os.path.join(args.path, "go.work")
            if os.path.exists(work_file):
                manifests.extend(parse_go_work(work_file))
            cand = os.path.join(args.path, "go.mod")
            if os.path.exists(cand) and cand not in manifests:
                manifests.append(cand)
        elif os.path.isfile(args.path) and args.path.endswith("go.mod"):
            manifests.append(args.path)

    if not manifests:
        print(
            f"{COLOR_RED}{ICON_ERROR} No go.mod or go.work found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    all_deps = {}
    all_dev_deps = {}
    all_local_replacements = {}
    all_excluded = {}
    all_retracted = {}

    for manifest in manifests:
        print(
            f"{COLOR_GRAY}{ICON_INFO} Reading {os.path.basename(manifest)}...{COLOR_RESET}"
        )
        deps, dev_deps, local_reps, ex_vers, ret_vers = parse_go_mod(manifest)
        all_deps.update(deps)
        all_dev_deps.update(dev_deps)
        all_local_replacements.update(local_reps)
        for k, v in ex_vers.items():
            all_excluded.setdefault(k, set()).update(v)
        for k, v in ret_vers.items():
            all_retracted.setdefault(k, set()).update(v)

    targets = []
    local_results = []

    for name, declared_ver in all_deps.items():
        if name in all_local_replacements:
            loc_path = all_local_replacements[name]
            local_results.append(
                {
                    "name": name,
                    "declared": declared_ver,
                    "installed": declared_ver,
                    "latest": f"Local ({loc_path})",
                    "latest_same_major": declared_ver,
                    "latest_absolute": declared_ver,
                    "status": "local",
                    "deprecated": None,
                    "error": None,
                    "repo_url": None,
                    "compare_url": None,
                    "releases_url": None,
                    "dep_type": "Direct",
                    "required_by": [],
                }
            )
        else:
            targets.append(
                {
                    "name": name,
                    "declared": declared_ver,
                    "installed": [declared_ver] if declared_ver else [],
                    "dep_type": "Direct",
                    "excluded_versions": all_excluded.get(name, set()),
                    "retracted_versions": all_retracted.get("_global", set()),
                }
            )

    for name, declared_ver in all_dev_deps.items():
        dep_kind = "Dev" if declared_ver == "tool" else "Transitive"
        if name in all_local_replacements:
            loc_path = all_local_replacements[name]
            local_results.append(
                {
                    "name": name,
                    "declared": declared_ver,
                    "installed": declared_ver,
                    "latest": f"Local ({loc_path})",
                    "latest_same_major": declared_ver,
                    "latest_absolute": declared_ver,
                    "status": "local",
                    "deprecated": None,
                    "error": None,
                    "repo_url": None,
                    "compare_url": None,
                    "releases_url": None,
                    "dep_type": dep_kind,
                    "required_by": ["indirect"] if dep_kind == "Transitive" else [],
                }
            )
        else:
            targets.append(
                {
                    "name": name,
                    "declared": declared_ver,
                    "installed": [declared_ver] if declared_ver else [],
                    "dep_type": dep_kind,
                    "excluded_versions": all_excluded.get(name, set()),
                    "retracted_versions": all_retracted.get("_global", set()),
                }
            )

    start_time = time.time()
    results = check_all_go_targets(targets, args.concurrent) if targets else []
    results.extend(local_results)

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["go"]
        osv_vulns = check_osv_vulnerabilities(
            [t for t in targets if t.get("installed")],
            tech_info["osv_ecosystem"],
            args.concurrent,
        )

        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])

            # Alert if an excluded version in go.mod could contain a fix for this vulnerability
            pkg_ex = all_excluded.get(r["name"], set())
            if pkg_ex and r.get("vulnerabilities"):
                r["excluded_warning"] = (
                    f"Version(s) {', '.join(sorted(pkg_ex))} are explicitly excluded in go.mod and may contain fix patches for detected vulnerabilities."
                )
    else:
        for r in results:
            r["vulnerabilities"] = []

    # Resolve exact parent dependency tree via GOPROXY
    parent_map = resolve_go_parent_graph(all_deps, getattr(args, "concurrent", 10))

    direct_keys = set(all_deps.keys())
    for r in results:
        if r["name"] not in direct_keys and r.get("dep_type") != "Dev":
            r["dep_type"] = "Transitive"
            pkg_parents = parent_map.get(r["name"])
            if pkg_parents:
                r["required_by"] = sorted(pkg_parents)
            else:
                r["required_by"] = ["indirect"]
        elif r["name"] in direct_keys:
            r["dep_type"] = "Direct"
            r["required_by"] = []

    # Verify go.sum checksums against sum.golang.org
    sum_file = None
    if os.path.isdir(args.path):
        cand_sum = os.path.join(args.path, "go.sum")
        if os.path.exists(cand_sum):
            sum_file = cand_sum
    elif os.path.isfile(args.path):
        cand_sum = os.path.join(os.path.dirname(args.path), "go.sum")
        if os.path.exists(cand_sum):
            sum_file = cand_sum

    verify_go_checksums(results, sum_file, getattr(args, "concurrent", 10))

    elapsed = time.time() - start_time

    return (
        results,
        {"dependencies": all_deps, "devDependencies": {}, "all_direct": all_deps},
        elapsed,
    )


# ==============================================================================
# Rust (Cargo) Scanning Logic
# ==============================================================================


def find_rust_files(path):
    """Finds Cargo.toml and Cargo.lock files, traversing parent directories for workspace Cargo.lock if needed."""
    toml_path = None
    lock_path = None

    abs_path = os.path.abspath(path)
    search_dir = abs_path
    if os.path.exists(abs_path):
        if os.path.isdir(abs_path):
            t = os.path.join(abs_path, "Cargo.toml")
            l = os.path.join(abs_path, "Cargo.lock")
            if os.path.exists(t):
                toml_path = t
            if os.path.exists(l):
                lock_path = l
            search_dir = abs_path
        elif os.path.isfile(abs_path):
            if abs_path.endswith("Cargo.toml"):
                toml_path = abs_path
                l = os.path.join(os.path.dirname(abs_path), "Cargo.lock")
                if os.path.exists(l):
                    lock_path = l
            elif abs_path.endswith("Cargo.lock"):
                lock_path = abs_path
                t = os.path.join(os.path.dirname(abs_path), "Cargo.toml")
                if os.path.exists(t):
                    toml_path = t
            search_dir = os.path.dirname(abs_path)

        # If lock_path is not found in immediate directory, search upwards for workspace Cargo.lock
        if not lock_path and search_dir:
            curr = os.path.dirname(search_dir)
            while curr and os.path.dirname(curr) != curr:
                candidate = os.path.join(curr, "Cargo.lock")
                if os.path.exists(candidate):
                    lock_path = candidate
                    break
                curr = os.path.dirname(curr)

    return toml_path, lock_path


def parse_cargo_toml(filepath):
    """Parses Cargo.toml to extract direct dependency names and declared version constraints.
    Returns a dict {dep_name: version_spec} that supports membership checks ('name' in deps) and key iteration.
    Supports Cargo workspaces and [workspace.dependencies].
    """
    dependencies = {}
    if not filepath or not os.path.exists(filepath):
        return dependencies

    # Look for workspace root Cargo.toml if this toml references workspace dependencies
    workspace_deps = {}
    curr = os.path.dirname(os.path.abspath(filepath))
    while curr and os.path.dirname(curr) != curr:
        ws_candidate = os.path.join(curr, "Cargo.toml")
        if os.path.exists(ws_candidate) and os.path.abspath(ws_candidate) != os.path.abspath(filepath):
            try:
                with open(ws_candidate, "rb") as wf:
                    ws_data = tomllib.load(wf)
                if "workspace" in ws_data and isinstance(ws_data["workspace"], dict):
                    raw_ws_deps = ws_data["workspace"].get("dependencies", {})
                    if isinstance(raw_ws_deps, dict):
                        for k, v in raw_ws_deps.items():
                            if isinstance(v, str):
                                workspace_deps[k] = v
                            elif isinstance(v, dict) and "version" in v:
                                workspace_deps[k] = str(v["version"])
                    break
            except Exception:
                pass
        curr = os.path.dirname(curr)

    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)

        def _add_deps_table(table):
            if not isinstance(table, dict):
                return
            for name, spec in table.items():
                if isinstance(spec, str):
                    dependencies[name] = spec
                elif isinstance(spec, dict):
                    if spec.get("workspace"):
                        dependencies[name] = workspace_deps.get(name, "workspace")
                    elif "version" in spec:
                        dependencies[name] = str(spec["version"])
                    elif "path" in spec:
                        dependencies[name] = spec["path"]
                    else:
                        dependencies[name] = "*"
                else:
                    dependencies[name] = str(spec)

        for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
            if sec in data and isinstance(data[sec], dict):
                _add_deps_table(data[sec])

        if "target" in data and isinstance(data["target"], dict):
            for _, t_val in data["target"].items():
                if isinstance(t_val, dict):
                    for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
                        if sec in t_val and isinstance(t_val[sec], dict):
                            _add_deps_table(t_val[sec])

        if "workspace" in data and isinstance(data["workspace"], dict):
            ws_d = data["workspace"].get("dependencies")
            if isinstance(ws_d, dict):
                _add_deps_table(ws_d)

    except Exception:
        # Fallback to line-by-line regex parsing if tomllib fails
        try:
            current_section = None
            is_specific_pkg_section = False
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m_sec = re.match(r"^\[([^\]]+)\]", line)
                    if m_sec:
                        current_section = m_sec.group(1).strip()
                        is_specific_pkg_section = False
                        m_sub = re.search(
                            r"(?:dependencies|dev-dependencies|build-dependencies)\.([a-zA-Z0-9_-]+)$",
                            current_section,
                        )
                        if m_sub:
                            dependencies[m_sub.group(1)] = "*"
                            is_specific_pkg_section = True
                        continue

                    is_dep_section = current_section in {
                        "dependencies",
                        "dev-dependencies",
                        "build-dependencies",
                    } or (
                        current_section
                        and (
                            "dependencies" in current_section
                            or "dev-dependencies" in current_section
                            or "build-dependencies" in current_section
                        )
                    )
                    if is_dep_section and not is_specific_pkg_section:
                        m_dep = re.match(r"^([a-zA-Z0-9_-]+)\s*=\s*(.*)$", line)
                        if m_dep:
                            dep_name = m_dep.group(1).strip()
                            dep_val = m_dep.group(2).strip().strip('"').strip("'")
                            if dep_name not in {
                                "version",
                                "optional",
                                "features",
                                "default-features",
                                "path",
                            }:
                                dependencies[dep_name] = dep_val or "*"
        except Exception as e:
            print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Cargo.toml: {e}{COLOR_RESET}")

    return dependencies


class CargoLockResult(tuple):
    """Subclass of tuple (resolved, parents) that also carries local_packages set for Cargo workspaces."""

    def __new__(cls, resolved, parents, local_packages=None):
        return super().__new__(cls, (resolved, parents))

    def __init__(self, resolved, parents, local_packages=None):
        self.resolved = resolved
        self.parents = parents
        self.local_packages = set(local_packages) if local_packages else set()


def parse_cargo_lock(filepath):
    """Parses Cargo.lock to extract all resolved package names, versions, and build parent tree.
    Supports Cargo Lockfile v4 using tomllib.
    """
    resolved = {}
    parents = {}
    local_packages = set()
    if not filepath or not os.path.exists(filepath):
        return CargoLockResult(resolved, parents, local_packages)

    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)

        packages = data.get("package", [])
        if isinstance(packages, list):
            for pkg in packages:
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name")
                version = pkg.get("version")
                source = pkg.get("source")
                if not name or not version:
                    continue

                resolved.setdefault(name, set()).add(version)
                if not source:
                    local_packages.add(name)

                deps = pkg.get("dependencies", [])
                if isinstance(deps, list):
                    for dep in deps:
                        if not isinstance(dep, str):
                            continue
                        dep_name = dep.split()[0] if dep else ""
                        if dep_name:
                            parents.setdefault(dep_name, set()).add(name)

    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Cargo.lock: {e}{COLOR_RESET}")

    resolved_clean = {k: list(v) for k, v in resolved.items()}
    parents_clean = {k: list(v) for k, v in parents.items()}
    return CargoLockResult(resolved_clean, parents_clean, local_packages)


def get_crates_index_url(crate_name):
    """Generates the official Cargo sparse index CDN URL for a crate."""
    name = crate_name.lower()
    length = len(name)
    if length == 1:
        prefix = f"1/{name}"
    elif length == 2:
        prefix = f"2/{name}"
    elif length == 3:
        prefix = f"3/{name[0]}/{name}"
    else:
        prefix = f"{name[:2]}/{name[2:4]}/{name}"
    return f"https://index.crates.io/{prefix}"


def check_rust_package(target):
    """Queries crates.io index/API for crate metadata and checks target version."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]
    is_local = target.get("is_local", False) or (
        declared
        and str(declared).startswith((".", "/", "path:", "workspace:", "file:"))
    )

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    # Handle local / path / internal workspace member crates without querying external registry
    if is_local:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": "Local",
                    "latest_same_major": None,
                    "latest_absolute": None,
                    "status": "local",
                    "deprecated": None,
                    "error": None,
                    "repo_url": None,
                    "compare_url": None,
                    "releases_url": None,
                }
            )
        return results

    try:
        all_versions = []
        yanked_versions = set()
        repo_url_raw = None
        latest_version = None

        # 1. Primary: Fast official CDN Cargo sparse index (no rate limits)
        url_index = get_crates_index_url(name)
        req_index = urllib.request.Request(url_index)
        fetched_index = False
        try:
            with safe_urlopen(req_index, timeout=10) as response:
                content = response.read().decode("utf-8", errors="ignore")
                for line in content.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        v_data = json.loads(line)
                        v_num = v_data.get("vers")
                        if v_num:
                            all_versions.append(v_num)
                            if v_data.get("yanked"):
                                yanked_versions.add(v_num)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass
                if all_versions:
                    fetched_index = True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Private/internal crate not in public crates.io index
                for ver_str in versions_to_check:
                    results.append(
                        {
                            "name": name,
                            "declared": declared,
                            "installed": ver_str,
                            "latest": "Local",
                            "latest_same_major": None,
                            "latest_absolute": None,
                            "status": "local",
                            "deprecated": None,
                            "error": None,
                            "repo_url": None,
                            "compare_url": None,
                            "releases_url": None,
                        }
                    )
                return results
        except (urllib.error.URLError, OSError, TimeoutError):
            pass

        # 2. Fallback: REST API if sparse index call failed or returned no versions
        if not fetched_index:
            url = f"{URL_RUST_REGISTRY}{urllib.parse.quote(name)}"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", f"Kevlar-CheckDeps/{VERSION}")

            with safe_urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))

            crate_info = data.get("crate", {})
            latest_version = crate_info.get("max_stable_version") or crate_info.get(
                "max_version"
            )
            repo_url_raw = crate_info.get("repository") or crate_info.get("homepage")

            versions_meta = data.get("versions", [])
            for v_meta in versions_meta:
                if v_meta.get("yanked"):
                    yanked_versions.add(v_meta.get("num"))

            all_versions = [v.get("num") for v in versions_meta if v.get("num")]

        for ver_str in versions_to_check:
            clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"

            latest_same_major, latest_absolute = find_latest_same_major(
                clean_ver, all_versions
            )
            if latest_version:
                latest_absolute = latest_version
            if not latest_same_major:
                latest_same_major = latest_absolute

            status = determine_update_type(
                clean_ver, latest_same_major, latest_absolute
            )

            is_deprecated = clean_ver in yanked_versions

            repo_url = None
            compare_url = None
            releases_url = None
            if status in {"major", "minor-major", "patch-major"}:
                if not repo_url_raw:
                    repo_url_raw = (
                        f"https://github.com/rust-lang/{name}"
                        if is_github_url(f"https://github.com/rust-lang/{name}")
                        else None
                    )
                repo_url = clean_repo_url(repo_url_raw)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = (
                        f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    )

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": ver_str,
                    "installed": clean_ver,
                    "latest": display_latest or "unknown",
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": status,
                    "deprecated": is_deprecated,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                }
            )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            for ver_str in versions_to_check:
                results.append(
                    {
                        "name": name,
                        "declared": declared,
                        "installed": ver_str,
                        "latest": "Local",
                        "latest_same_major": None,
                        "latest_absolute": None,
                        "status": "local",
                        "deprecated": None,
                        "error": None,
                        "repo_url": None,
                        "compare_url": None,
                        "releases_url": None,
                    }
                )
        else:
            for ver_str in versions_to_check:
                results.append(
                    {
                        "name": name,
                        "declared": ver_str,
                        "installed": ver_str,
                        "latest": "unknown",
                        "status": "error",
                        "deprecated": False,
                        "error": _sanitize_error_message(e, name),
                    }
                )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": ver_str,
                    "installed": ver_str,
                    "latest": "unknown",
                    "status": "error",
                    "deprecated": False,
                    "error": _sanitize_error_message(e, name),
                }
            )

    return results


def check_all_rust_targets(targets, max_workers):
    """Checks all Rust target crates in parallel."""
    rust_workers = min(max_workers, 5) if max_workers else 5
    return _check_all_targets_unified(
        targets, check_rust_package, "[Rust] Checking registry", rust_workers
    )


def run_rust_checker(args):
    """Main orchestrator for Rust Cargo checker."""
    toml_path, lock_path = find_rust_files(args.path)
    if not toml_path and not lock_path:
        print(
            f"{COLOR_RED}{ICON_ERROR} No Cargo.toml or Cargo.lock found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    print(f"{COLOR_GRAY}{ICON_INFO} Reading Cargo files...{COLOR_RESET}")
    direct_deps = parse_cargo_toml(toml_path)
    direct = set(direct_deps.keys()) if isinstance(direct_deps, dict) else set(direct_deps)
    lock_result = parse_cargo_lock(lock_path)
    resolved, parents = lock_result[0], lock_result[1]
    local_packages = getattr(lock_result, "local_packages", set())

    if not resolved and direct_deps:
        resolved = {
            name: [
                direct_deps.get(name)
                if isinstance(direct_deps, dict)
                and direct_deps.get(name)
                and direct_deps.get(name) != "workspace"
                and not str(direct_deps.get(name)).startswith(".")
                else "0.0.0"
            ]
            for name in direct
        }

    pkg_data = {
        "all_direct": {
            name: (direct_deps.get(name, name) if isinstance(direct_deps, dict) else name)
            for name in direct
        },
        "dependencies": resolved,
    }

    targets = []
    for name, versions in resolved.items():
        if not args.all and name not in direct:
            continue
        declared = direct_deps.get(name) if isinstance(direct_deps, dict) else (versions[0] if versions else None)
        is_local = (name in local_packages) or (
            declared and str(declared).startswith((".", "/", "path:", "workspace:"))
        )
        if not declared or declared == "workspace" or str(declared).startswith("."):
            declared = versions[0] if versions else "0.0.0"
        targets.append(
            {
                "name": name,
                "declared": declared,
                "installed": versions if versions != ["0.0.0"] else [],
                "is_local": is_local,
            }
        )

    if not targets:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No Rust packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    results = check_all_rust_targets(targets, args.concurrent)

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["rust"]
        osv_vulns = check_osv_vulnerabilities(
            targets, tech_info["osv_ecosystem"], args.concurrent
        )

        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []

    # Resolve transitive dependency parents & dep_type
    for r in results:
        if r["name"] in direct:
            r["dep_type"] = "Direct"
            if isinstance(direct_deps, dict) and direct_deps.get(r["name"]):
                dec_val = direct_deps[r["name"]]
                if dec_val != "workspace" and not str(dec_val).startswith("."):
                    r["declared"] = dec_val
        else:
            r["dep_type"] = "Transitive"
            r["declared"] = None
        direct_parents = find_direct_parents(r["name"], parents, direct)
        r["required_by"] = sorted(direct_parents - {r["name"]})

    elapsed = time.time() - start_time

    return results, pkg_data, elapsed


# ==============================================================================
# Ruby (Bundler) Scanning Logic
# ==============================================================================


def find_ruby_files(path):
    """Finds Gemfile and Gemfile.lock files."""
    gemfile_path = None
    lock_path = None

    if os.path.exists(path):
        if os.path.isdir(path):
            g = os.path.join(path, "Gemfile")
            l = os.path.join(path, "Gemfile.lock")
            if os.path.exists(g):
                gemfile_path = g
            if os.path.exists(l):
                lock_path = l
        elif os.path.isfile(path):
            if path.endswith("Gemfile"):
                gemfile_path = path
                l = os.path.join(os.path.dirname(path), "Gemfile.lock")
                if os.path.exists(l):
                    lock_path = l
            elif path.endswith("Gemfile.lock"):
                lock_path = path
                g = os.path.join(os.path.dirname(path), "Gemfile")
                if os.path.exists(g):
                    gemfile_path = g

    return gemfile_path, lock_path


def parse_gemfile(filepath):
    """Parses Gemfile to extract direct dependency names."""
    dependencies = set()
    if not filepath or not os.path.exists(filepath):
        return dependencies

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # gem 'rails', '~> 6.0' or gem "nokogiri"
                m = re.match(r'^gem\s+[\'"]([^\'"]+)[\'"]', line)
                if m:
                    dependencies.add(m.group(1).strip())
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Gemfile: {e}{COLOR_RESET}")

    return dependencies


def parse_gemfile_lock(filepath):
    """Parses Gemfile.lock to extract all resolved package names, versions, and build parent tree."""
    resolved = {}
    parents = {}
    if not filepath or not os.path.exists(filepath):
        return resolved, parents

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_specs = False
        current_parent = None
        spec_indent = None

        for line in lines:
            if not line.strip():
                continue

            # Check for root sections (no indentation)
            if line and not line.startswith(" ") and not line.startswith("\t"):
                in_specs = False
                continue

            line_stripped = line.strip()
            if line_stripped == "specs:":
                in_specs = True
                spec_indent = None
                current_parent = None
                continue

            if in_specs:
                # Count leading spaces
                leading_spaces = len(line) - len(line.lstrip(" "))

                # Try to match gem version pattern: "    name (version)"
                m_spec = re.match(r"^\s*([a-zA-Z0-9_-]+)\s*\(([^)]+)\)", line)
                if m_spec:
                    name = m_spec.group(1)
                    version = m_spec.group(2)

                    if spec_indent is None:
                        spec_indent = leading_spaces

                    if leading_spaces == spec_indent:
                        current_parent = name
                        resolved[current_parent] = version
                        continue

                # If it has more indentation than spec_indent and matches child dep, it's a child dependency
                if (
                    spec_indent is not None
                    and leading_spaces > spec_indent
                    and current_parent
                ):
                    m_dep = re.match(r"^\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]+)\))?", line)
                    if m_dep:
                        child = m_dep.group(1)
                        if child not in parents:
                            parents[child] = set()
                        parents[child].add(current_parent)

    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Gemfile.lock: {e}{COLOR_RESET}"
        )

    parents_clean = {k: list(v) for k, v in parents.items()}
    return resolved, parents_clean


def check_ruby_package(target):
    """Queries rubygems.org API for package metadata and checks target version."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]

    versions_to_check = installed_versions if installed_versions else [declared]
    results = []

    try:
        try:
            url_versions = (
                f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(name)}.json"
            )
            req_v = urllib.request.Request(url_versions)
            with safe_urlopen(req_v, timeout=10) as response:
                versions_data = json.loads(response.read().decode("utf-8"))

            stable_versions = []
            all_versions = []
            for item in versions_data:
                v_num = item.get("number")
                if v_num:
                    all_versions.append(v_num)
                    if not item.get("prerelease"):
                        stable_versions.append(v_num)
            valid_versions = stable_versions if stable_versions else all_versions
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            try:
                url_fallback = f"{URL_RUBY_REGISTRY}{urllib.parse.quote(name)}.json"
                req_fb = urllib.request.Request(url_fallback)
                with safe_urlopen(req_fb, timeout=10) as response:
                    data_fb = json.loads(response.read().decode("utf-8"))
                latest_version = data_fb.get("version")
                valid_versions = [latest_version] if latest_version else []
            except Exception:
                valid_versions = []
        except Exception:
            # Fallback to single latest version endpoint
            try:
                url_fallback = f"{URL_RUBY_REGISTRY}{urllib.parse.quote(name)}.json"
                req_fb = urllib.request.Request(url_fallback)
                with safe_urlopen(req_fb, timeout=10) as response:
                    data_fb = json.loads(response.read().decode("utf-8"))
                latest_version = data_fb.get("version")
                valid_versions = [latest_version] if latest_version else []
            except Exception:
                valid_versions = []

        for ver_str in versions_to_check:
            clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"

            latest_same_major, latest_absolute = find_latest_same_major(
                clean_ver, valid_versions
            )
            if not latest_same_major:
                latest_same_major = latest_absolute

            status = determine_update_type(
                clean_ver, latest_same_major, latest_absolute
            )

            repo_url = None
            compare_url = None
            releases_url = None
            if status in {"major", "minor-major", "patch-major"}:
                try:
                    url_gem = f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json"
                    req_g = urllib.request.Request(url_gem)
                    with safe_urlopen(req_g, timeout=5) as response:
                        data_g = json.loads(response.read().decode("utf-8"))
                    raw_url = data_g.get("source_code_uri") or data_g.get(
                        "homepage_uri"
                    )
                    repo_url = clean_repo_url(raw_url)
                    if repo_url:
                        compare_url = get_compare_url(
                            repo_url, clean_ver, latest_absolute
                        )
                        releases_url = (
                            f"{repo_url}/releases"
                            if is_github_url(repo_url)
                            else repo_url
                        )
                except (KeyError, ValueError, TypeError):
                    pass

            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append(
                {
                    "name": name,
                    "declared": ver_str,
                    "installed": clean_ver,
                    "latest": display_latest or "unknown",
                    "latest_same_major": latest_same_major,
                    "latest_absolute": latest_absolute,
                    "status": status,
                    "deprecated": False,
                    "error": None,
                    "repo_url": repo_url,
                    "compare_url": compare_url,
                    "releases_url": releases_url,
                }
            )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            for ver_str in versions_to_check:
                clean_ver = RE_CLEAN_VER.sub("", ver_str) if ver_str else "0.0.0"
                if not clean_ver:
                    clean_ver = "0.0.0"
                results.append(
                    {
                        "name": name,
                        "declared": declared,
                        "installed": clean_ver,
                        "latest": "Local",
                        "latest_same_major": None,
                        "latest_absolute": None,
                        "status": "local",
                        "deprecated": False,
                        "error": None,
                        "repo_url": None,
                        "compare_url": None,
                        "releases_url": None,
                    }
                )
        else:
            error_msg = f"HTTP {e.code}"
            for ver_str in versions_to_check:
                results.append(
                    {
                        "name": name,
                        "declared": declared,
                        "installed": ver_str,
                        "latest": None,
                        "status": "error",
                        "deprecated": False,
                        "error": error_msg,
                    }
                )
    except Exception as e:
        for ver_str in versions_to_check:
            results.append(
                {
                    "name": name,
                    "declared": ver_str,
                    "installed": ver_str,
                    "latest": "unknown",
                    "status": "error",
                    "deprecated": False,
                    "error": str(e),
                }
            )

    return results


def check_all_ruby_targets(targets, max_workers):
    """Checks all Ruby target gems in parallel."""
    return _check_all_targets_unified(
        targets, check_ruby_package, "[Ruby] Checking registry", max_workers
    )


def run_ruby_checker(args):
    """Main orchestrator for Ruby Bundler checker."""
    gemfile_path, lock_path = find_ruby_files(args.path)
    if not gemfile_path and not lock_path:
        print(
            f"{COLOR_RED}{ICON_ERROR} No Gemfile or Gemfile.lock found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    print(f"{COLOR_GRAY}{ICON_INFO} Reading Gemfile files...{COLOR_RESET}")
    direct = parse_gemfile(gemfile_path)
    resolved, parents = parse_gemfile_lock(lock_path)

    if not resolved and direct:
        resolved = {name: "0.0.0" for name in direct}

    pkg_data = {"all_direct": {name: name for name in direct}, "dependencies": resolved}

    targets = []
    for name, version in resolved.items():
        if not args.all and name not in direct:
            continue
        targets.append(
            {
                "name": name,
                "declared": version,
                "installed": [version] if version != "0.0.0" else [],
            }
        )

    if not targets:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No Ruby packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    results = check_all_ruby_targets(targets, args.concurrent)

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["ruby"]
        osv_vulns = check_osv_vulnerabilities(
            targets, tech_info["osv_ecosystem"], args.concurrent
        )

        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []

    # Resolve transitive dependency parents
    for r in results:
        direct_parents = find_direct_parents(r["name"], parents, direct)
        r["required_by"] = sorted(direct_parents - {r["name"]})

    elapsed = time.time() - start_time

    return results, pkg_data, elapsed


# ==============================================================================
# Gradle Scanning Logic
# ==============================================================================


def find_gradle_files(path):
    """Finds build.gradle, build.gradle.kts and lockfiles."""
    gradle_files = []
    lock_files = []

    if os.path.exists(path):
        if os.path.isdir(path):
            for name in ("build.gradle", "build.gradle.kts"):
                p = os.path.join(path, name)
                if os.path.exists(p):
                    gradle_files.append(p)
            lock_dir = os.path.join(path, "gradle", "dependency-locks")
            if os.path.exists(lock_dir) and os.path.isdir(lock_dir):
                try:
                    for f in os.listdir(lock_dir):
                        if f.endswith(".lockfile"):
                            lock_files.append(os.path.join(lock_dir, f))
                except OSError:
                    pass
            gl = os.path.join(path, "gradle.lockfile")
            if os.path.exists(gl):
                lock_files.append(gl)
        elif os.path.isfile(path):
            if path.endswith((".gradle", ".gradle.kts")):
                gradle_files.append(path)
            elif path.endswith(".lockfile"):
                lock_files.append(path)

    return gradle_files, lock_files


def parse_libs_versions_toml(filepath):
    """Parses libs.versions.toml to extract version catalog declarations.
    Returns:
        dict: group:name -> version
    """
    dependencies = {}
    if not filepath or not os.path.exists(filepath):
        return dependencies

    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)

        versions = {}
        raw_versions = data.get("versions", {})
        if isinstance(raw_versions, dict):
            for k, v in raw_versions.items():
                if isinstance(v, str):
                    versions[k] = v
                elif isinstance(v, dict):
                    for key in ("require", "prefer", "strictly"):
                        if key in v:
                            versions[k] = v[key]
                            break
                    else:
                        versions[k] = "*"

        libraries = data.get("libraries", {})
        if isinstance(libraries, dict):
            for val in libraries.values():
                group = ""
                name = ""
                ver = "*"

                if isinstance(val, str):
                    parts = val.split(":")
                    if len(parts) >= 2:
                        group = parts[0].strip()
                        name = parts[1].strip()
                        ver = parts[2].strip() if len(parts) > 2 else "*"
                elif isinstance(val, dict):
                    if "module" in val:
                        module_val = val["module"]
                        if isinstance(module_val, str):
                            m_parts = module_val.split(":")
                            if len(m_parts) >= 2:
                                group = m_parts[0].strip()
                                name = m_parts[1].strip()
                    else:
                        g_val = val.get("group")
                        n_val = val.get("name")
                        if isinstance(g_val, str):
                            group = g_val.strip()
                        if isinstance(n_val, str):
                            name = n_val.strip()

                    # Extract version
                    ver_val = val.get("version")
                    if isinstance(ver_val, str):
                        ver = ver_val
                    elif isinstance(ver_val, dict):
                        if "ref" in ver_val:
                            ref_name = ver_val["ref"]
                            ref_val = versions.get(ref_name, "*")
                            ver = ref_val
                        else:
                            for key in ("require", "prefer", "strictly"):
                                if key in ver_val:
                                    ver = ver_val[key]
                                    break

                    if ver == "*":
                        v_ref = val.get("versionRef")
                        if isinstance(v_ref, str):
                            ver = versions.get(v_ref, "*")

                if group and name:
                    dependencies[f"{group}:{name}"] = ver if ver else "*"

    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning reading libs.versions.toml: {e}{COLOR_RESET}"
        )

    return dependencies


def parse_gradle_build(filepath):
    """Parses build.gradle / build.gradle.kts to extract direct dependencies."""
    dependencies = {}
    if not filepath or not os.path.exists(filepath):
        return dependencies

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Pattern 1: group:artifact:version in configuration calls
        for m in RE_GRADLE_CONFIG.finditer(content):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            version = m.group(3).strip()
            dependencies[f"{group}:{artifact}"] = version

        # Pattern 2: group: "...", name: "...", version: "..."
        for m in RE_GRADLE_MAP1.finditer(content):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            version = m.group(3).strip()
            dependencies[f"{group}:{artifact}"] = version

        # Pattern 3: group = "...", name = "...", version = "..."
        for m in RE_GRADLE_MAP2.finditer(content):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            version = m.group(3).strip()
            dependencies[f"{group}:{artifact}"] = version

    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Gradle build file: {e}{COLOR_RESET}"
        )

    return dependencies


def parse_gradle_lockfile(filepath):
    """Parses gradle .lockfile to extract resolved dependencies."""
    resolved = {}
    if not filepath or not os.path.exists(filepath):
        return resolved

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([^:]+):([^:]+):([^=]+)=", line)
                if m:
                    group = m.group(1).strip()
                    artifact = m.group(2).strip()
                    version = m.group(3).strip()
                    resolved[f"{group}:{artifact}"] = version
    except Exception as e:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Gradle lockfile: {e}{COLOR_RESET}"
        )

    return resolved


def run_gradle_checker(args):
    """Main orchestrator for Gradle dependency checker."""
    build_files, lock_files = find_gradle_files(args.path)

    catalog_file = None
    if os.path.exists(args.path):
        if os.path.isdir(args.path):
            cand = os.path.join(args.path, "gradle", "libs.versions.toml")
            if os.path.exists(cand):
                catalog_file = cand
        elif os.path.isfile(args.path) and args.path.endswith("libs.versions.toml"):
            catalog_file = args.path

    if not build_files and not lock_files and not catalog_file:
        print(
            f"{COLOR_RED}{ICON_ERROR} No build.gradle, build.gradle.kts, lockfiles or gradle/libs.versions.toml found in: {args.path}{COLOR_RESET}"
        )
        return None, None, 0

    print(f"{COLOR_GRAY}{ICON_INFO} Reading Gradle files...{COLOR_RESET}")

    direct = {}
    if catalog_file:
        print(
            f"{COLOR_GRAY}{ICON_INFO} Reading Gradle Version Catalog (libs.versions.toml)...{COLOR_RESET}"
        )
        direct.update(parse_libs_versions_toml(catalog_file))

    for f in build_files:
        direct.update(parse_gradle_build(f))

    resolved = {}
    for lf in lock_files:
        resolved.update(parse_gradle_lockfile(lf))

    if not resolved:
        resolved = direct

    pkg_data = {"all_direct": {name: name for name in direct}, "dependencies": resolved}

    targets = []
    for name, version in resolved.items():
        if not args.all and name not in direct:
            continue
        targets.append(
            {
                "name": name,
                "declared": version,
                "installed": [version] if version != "0.0.0" else [],
            }
        )

    if not targets:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No Gradle packages identified to check.{COLOR_RESET}"
        )
        return None, None, 0

    start_time = time.time()
    # Reuses Maven Central checking logic
    results = check_all_maven_targets(targets, args.concurrent)

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["gradle"]
        osv_vulns = check_osv_vulnerabilities(
            targets, tech_info["osv_ecosystem"], args.concurrent
        )

        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []

    # Resolve transitive dependency parents
    for r in results:
        if r["name"] not in direct:
            r["required_by"] = ["transitive"]
        else:
            r["required_by"] = []

    elapsed = time.time() - start_time

    return results, pkg_data, elapsed


def validate_configuration_drift(results):
    """
    Validates that the installed version of each package satisfies the declared constraint.
    If validation fails, changes the package's status to 'error' and sets a descriptive error message.
    """
    if not results:
        return

    for r in results:
        declared = r.get("declared")
        installed = r.get("installed")

        if not declared or not installed:
            continue
        if str(declared).strip().lower() in {"n/a", "unknown", "", "transitive"}:
            continue
        if r.get("dep_type") == "Transitive" or (
            r.get("required_by") and not r.get("is_direct", False)
        ):
            continue
        if str(installed).strip().lower() in {"n/a", "unknown", ""}:
            continue

        decl_str = str(declared).strip()
        inst_str = str(installed).strip()

        # Skip checking if declared constraint is a git URL, local path, workspace, patch, catalog reference, etc.
        if (
            decl_str.startswith(("@", "git+", "git:", "http:", "https:", "ssh:", "file:", "workspace:", "patch:", "portal:", "link:", "catalog:", ".", "/")) or "github:" in decl_str.lower()
        ):
            continue

        # Strip Yarn Berry npm: prefix from the declared constraint
        # e.g., npm:esbuild-wasm@^0.23.0 -> ^0.23.0
        if decl_str.startswith("npm:"):
            rest = decl_str[4:]
            if rest.startswith("@"):
                parts = rest[1:].split("@", 1)
                if len(parts) == 2:
                    decl_str = parts[1]
            else:
                parts = rest.split("@", 1)
                if len(parts) == 2:
                    decl_str = parts[1]

        # Ensure we can extract a valid semantic version from installed version
        if parse_semver(inst_str) == (0, 0, 0, 0, 0, ""):
            continue

        try:
            satisfied = check_semver_satisfies(inst_str, decl_str)
        except Exception:
            satisfied = True

        if not satisfied:
            r["status"] = "error"
            r["error"] = (
                f"Configuration Drift: Installed version '{inst_str}' violates declared constraint '{decl_str}'"
            )


# ==============================================================================
# Output Formatting and Reporting
# ==============================================================================


class TerminalTextFormatter:
    """Utility class for terminal visual text formatting and character width calculations."""

    @staticmethod
    def get_char_width(char):
        """Returns visual terminal width of a character."""
        if char in {"🚫", "🛡️", "🛡"}:
            return 2
        w = unicodedata.east_asian_width(char)
        if w in {"W", "F"}:
            return 2
        if ord(char) > 0xFFFF:
            return 2
        return 1

    @staticmethod
    def visual_len(s):
        """Calculates visual terminal length of a string, ignoring ANSI codes."""
        clean_s = re.sub(r"\033\[[0-9;]*[a-zA-Z]", "", s)
        return sum(TerminalTextFormatter.get_char_width(c) for c in clean_s)

    @staticmethod
    def pad_string(text, width, align="left"):
        """Pads a string (potentially containing ANSI codes and wide chars) to target width."""
        vlen = TerminalTextFormatter.visual_len(text)
        if vlen >= width:
            return text
        diff = width - vlen
        if align == "left":
            return text + (" " * diff)
        elif align == "right":
            return (" " * diff) + text
        else:  # center
            left = diff // 2
            right = diff - left
            return (" " * left) + text + (" " * right)


def _filter_table_results(results, show_all, vuls_enabled):
    filtered = []
    for r in results:
        is_issue = (
            r["status"] in {"major", "minor", "patch"}
            or r["deprecated"]
            or r["status"] == "error"
            or (vuls_enabled and r.get("vulnerabilities"))
            or r.get("missing_checksum")
            or r.get("weak_checksum")
            or r.get("mismatch_checksum")
        )
        if show_all or is_issue:
            filtered.append(r)
    return filtered


def _format_status_badge(r):
    status_str = r["status"]
    color = COLOR_RESET
    icon = ""

    if status_str == "up-to-date":
        color, status_display, icon = COLOR_GREEN, "Up-to-date", ICON_OK
    elif status_str == "patch":
        color, status_display, icon = COLOR_CYAN, "Patch Update", ICON_WARN
    elif status_str == "minor":
        color, status_display, icon = COLOR_YELLOW, "Minor Update", ICON_WARN
    elif status_str == "major":
        color, status_display, icon = COLOR_RED, "Major Update", ICON_ERROR
    elif status_str == "error":
        color, status_display, icon = COLOR_GRAY, "Error", ICON_ERROR
    elif status_str == "local":
        color, status_display, icon = COLOR_CYAN, "Verify Local", "🔍"
    elif status_str == "minor-major":
        color, status_display, icon = COLOR_RED, "Minor/Major", ICON_ERROR
    elif status_str == "patch-major":
        color, status_display, icon = COLOR_RED, "Patch/Major", ICON_ERROR
    else:
        status_display = status_str

    if r["deprecated"]:
        status_display = "Deprecated"
        color = COLOR_MAGENTA
        icon = ICON_DEPRECATED

    return f"{color}{icon} {status_display}{COLOR_RESET}"


def _print_table_notes_and_diffs(filtered_results):
    notes_to_print = []
    for r in filtered_results:
        parent_suffix = f" (via {', '.join(r['required_by'])})" if r.get("required_by") else ""
        if r["deprecated"]:
            notes_to_print.append(f"  {COLOR_MAGENTA}{ICON_DEPRECATED} {r['name']}@{r['installed']}{parent_suffix}: {r['deprecated']}{COLOR_RESET}")
        elif r["status"] == "error" and r["error"]:
            notes_to_print.append(f"  {COLOR_RED}{ICON_ERROR} {r['name']}{parent_suffix}: {r['error']}{COLOR_RESET}")

        if r.get("missing_checksum"):
            notes_to_print.append(f"  {COLOR_YELLOW}{ICON_WARN} {r['name']}@{r['installed']}{parent_suffix}: Missing integrity checksum in lockfile{COLOR_RESET}")
        elif r.get("weak_checksum"):
            notes_to_print.append(f"  {COLOR_YELLOW}{ICON_WARN} {r['name']}@{r['installed']}{parent_suffix}: Weak checksum (SHA-1) in lockfile{COLOR_RESET}")

        if r.get("mismatch_checksum"):
            notes_to_print.append(f"  {COLOR_RED}{ICON_ERROR} {r['name']}@{r['installed']}{parent_suffix}: INTEGRITY MISMATCH! Lockfile checksum does not match official registry checksum.{COLOR_RESET}")

    if notes_to_print:
        print(f"\n{COLOR_BOLD}Notes & Warnings:{COLOR_RESET}")
        for note in notes_to_print:
            print(note)

    major_diffs_to_print = []
    for r in filtered_results:
        if r["status"] in {"major", "minor-major", "patch-major"} and r.get("compare_url"):
            major_diffs_to_print.append(f"  {COLOR_BOLD}{r['name']}{COLOR_RESET}: {COLOR_CYAN}{r['compare_url']}{COLOR_RESET}")

    if major_diffs_to_print:
        print(f"\n{COLOR_BOLD}Major Update Diffs:{COLOR_RESET}")
        for diff_note in major_diffs_to_print:
            print(diff_note)


def _print_table_vulnerabilities(filtered_results):
    vuls_to_print = []
    suppressed_to_print = []
    severity_order = {"malicious": 5, "critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

    for r in filtered_results:
        vuls_list = r.get("vulnerabilities", [])
        if vuls_list:
            sorted_v = sorted(vuls_list, key=lambda v: severity_order.get(get_severity_level(v), 0), reverse=True)
            vuls_to_print.append((r["name"], r["installed"] if r["installed"] else r["declared"], sorted_v, r.get("required_by", [])))

        suppressed_list = r.get("suppressed_vulnerabilities", [])
        if suppressed_list:
            suppressed_to_print.append((r["name"], r["installed"] if r["installed"] else r["declared"], suppressed_list, r.get("required_by", [])))

    if vuls_to_print:
        vuls_to_print.sort(key=lambda x: (
            -max(severity_order.get(get_severity_level(v), 0) for v in x[2]) if x[2] else 1,
            x[0].lower()
        ))
        print(f"\n{COLOR_BOLD}{COLOR_RED}{ICON_SHIELD} Security Vulnerabilities Details:{COLOR_RESET}")
        for name, ver, v_list, required_by in vuls_to_print:
            parent_suffix = f" (via {', '.join(required_by)})" if required_by else ""
            print(f"  {COLOR_BOLD}{name}@{ver}{parent_suffix}{COLOR_RESET} ({len(v_list)} vulnerabilities found):")
            for vuln in v_list:
                vid, severity, summary = vuln["id"], vuln["severity"], vuln["summary"]
                level = get_severity_level(vuln)
                sev_color = COLOR_RED + COLOR_BOLD if level == "malicious" else COLOR_RED if level in {"critical", "high"} else COLOR_YELLOW if level == "medium" else COLOR_CYAN if level == "low" else COLOR_GRAY
                display_severity = "MALICIOUS CODE" if level == "malicious" else severity
                print(f"    - {COLOR_BOLD}{vid}{COLOR_RESET} [{sev_color}{display_severity}{COLOR_RESET}]: {summary}")

    if suppressed_to_print:
        print(f"\n{COLOR_BOLD}{COLOR_GRAY}{ICON_INFO} Suppressed Vulnerabilities (Ignored):{COLOR_RESET}")
        for name, ver, s_list, required_by in suppressed_to_print:
            parent_suffix = f" (via {', '.join(required_by)})" if required_by else ""
            print(f"  {COLOR_BOLD}{COLOR_GRAY}{name}@{ver}{parent_suffix}{COLOR_RESET} ({len(s_list)} suppressed):")
            for vuln in s_list:
                vid = vuln["id"]
                reason = vuln.get("suppressed_reason", "No reason provided")
                summary = vuln["summary"]
                print(f"    - {COLOR_BOLD}{COLOR_GRAY}{vid}{COLOR_RESET}: {summary} {COLOR_GRAY}(Reason: {reason}){COLOR_RESET}")


def print_results_table(
    results, pkg_data, show_all, vuls_enabled=False, no_show_console=False
):
    """Draws a beautiful styled console report table with precise alignment."""
    if no_show_console:
        return

    filtered_results = _filter_table_results(results, show_all, vuls_enabled)
    if not filtered_results:
        print(f"\n{COLOR_GREEN}{ICON_OK} All dependencies are up-to-date and secure!{COLOR_RESET}\n")
        return

    col_name, col_type, col_dec, col_inst, col_latest, col_status, col_vuls = "Package", "Type", "Declared", "Installed", "Latest", "Status", "Vuls"
    w_name = max(len(col_name), max(len(r["name"]) for r in filtered_results)) + 2
    w_type = 12
    w_dec = max(len(col_dec), max(len(r["declared"] or "N/A") for r in filtered_results)) + 2
    w_inst = max(len(col_inst), max(len(r["installed"] or "N/A") for r in filtered_results)) + 2
    w_latest = max(len(col_latest), max(len(r["latest"] or "N/A") for r in filtered_results)) + 2
    w_status = 15
    w_vuls = 8
    t = BORDER_CHARS

    if vuls_enabled:
        border_top = f"{t['top_left']}{t['horizontal'] * w_name}{t['top_join']}{t['horizontal'] * w_type}{t['top_join']}{t['horizontal'] * w_dec}{t['top_join']}{t['horizontal'] * w_inst}{t['top_join']}{t['horizontal'] * w_latest}{t['top_join']}{t['horizontal'] * w_status}{t['top_join']}{t['horizontal'] * w_vuls}{t['top_right']}"
        border_mid = f"{t['mid_left']}{t['horizontal'] * w_name}{t['mid_join']}{t['horizontal'] * w_type}{t['mid_join']}{t['horizontal'] * w_dec}{t['mid_join']}{t['horizontal'] * w_inst}{t['mid_join']}{t['horizontal'] * w_latest}{t['mid_join']}{t['horizontal'] * w_status}{t['mid_join']}{t['horizontal'] * w_vuls}{t['mid_right']}"
        border_bot = f"{t['bot_left']}{t['horizontal'] * w_name}{t['bot_join']}{t['horizontal'] * w_type}{t['bot_join']}{t['horizontal'] * w_dec}{t['bot_join']}{t['horizontal'] * w_inst}{t['bot_join']}{t['horizontal'] * w_latest}{t['bot_join']}{t['horizontal'] * w_status}{t['bot_join']}{t['horizontal'] * w_vuls}{t['bot_right']}"
    else:
        border_top = f"{t['top_left']}{t['horizontal'] * w_name}{t['top_join']}{t['horizontal'] * w_type}{t['top_join']}{t['horizontal'] * w_dec}{t['top_join']}{t['horizontal'] * w_inst}{t['top_join']}{t['horizontal'] * w_latest}{t['top_join']}{t['horizontal'] * w_status}{t['top_right']}"
        border_mid = f"{t['mid_left']}{t['horizontal'] * w_name}{t['mid_join']}{t['horizontal'] * w_type}{t['mid_join']}{t['horizontal'] * w_dec}{t['mid_join']}{t['horizontal'] * w_inst}{t['mid_join']}{t['horizontal'] * w_latest}{t['mid_join']}{t['horizontal'] * w_status}{t['mid_right']}"
        border_bot = f"{t['bot_left']}{t['horizontal'] * w_name}{t['bot_join']}{t['horizontal'] * w_type}{t['bot_join']}{t['horizontal'] * w_dec}{t['bot_join']}{t['horizontal'] * w_inst}{t['bot_join']}{t['horizontal'] * w_latest}{t['bot_join']}{t['horizontal'] * w_status}{t['bot_right']}"

    print(border_top)
    hdr_name = TerminalTextFormatter.pad_string(f" {col_name}", w_name, align="left")
    hdr_type = TerminalTextFormatter.pad_string(col_type, w_type, align="center")
    hdr_dec = TerminalTextFormatter.pad_string(col_dec, w_dec, align="center")
    hdr_inst = TerminalTextFormatter.pad_string(col_inst, w_inst, align="center")
    hdr_latest = TerminalTextFormatter.pad_string(col_latest, w_latest, align="center")
    hdr_status = TerminalTextFormatter.pad_string(col_status, w_status, align="center")
    hdr_vuls = TerminalTextFormatter.pad_string(col_vuls, w_vuls, align="center")

    if vuls_enabled:
        print(f"{t['vertical']}{hdr_name}{t['vertical']}{hdr_type}{t['vertical']}{hdr_dec}{t['vertical']}{hdr_inst}{t['vertical']}{hdr_latest}{t['vertical']}{hdr_status}{t['vertical']}{hdr_vuls}{t['vertical']}")
    else:
        print(f"{t['vertical']}{hdr_name}{t['vertical']}{hdr_type}{t['vertical']}{hdr_dec}{t['vertical']}{hdr_inst}{t['vertical']}{hdr_latest}{t['vertical']}{hdr_status}{t['vertical']}")

    print(border_mid)

    for r in filtered_results:
        dep_type = r.get("dep_type")
        if not dep_type:
            dep_type = "Transitive"
            if r.get("is_engine", False):
                dep_type = "Engine"
            elif pkg_data:
                if r["name"] in pkg_data.get("all_direct", {}):
                    dep_type = "Direct"
                elif r["name"] in pkg_data.get("devDependencies", {}):
                    dep_type = "Dev"
                elif r["name"] in pkg_data.get("dependencies", {}):
                    dep_type = "Direct"

        styled_status = _format_status_badge(r)
        name_cell = TerminalTextFormatter.pad_string(f" {r['name']}", w_name, align="left")
        type_cell = TerminalTextFormatter.pad_string(dep_type, w_type, align="center")
        dec_cell = TerminalTextFormatter.pad_string(r["declared"] or "N/A", w_dec, align="center")
        inst_cell = TerminalTextFormatter.pad_string(r["installed"] or "N/A", w_inst, align="center")
        latest_cell = TerminalTextFormatter.pad_string(r["latest"] or "N/A", w_latest, align="center")
        status_cell = TerminalTextFormatter.pad_string(styled_status, w_status, align="center")

        if vuls_enabled:
            vuls_list = r.get("vulnerabilities", [])
            vuls_count = len(vuls_list)
            styled_vuls = f"{COLOR_RED}{COLOR_BOLD}{vuls_count}{COLOR_RESET}" if vuls_count > 0 else (f"{COLOR_GREEN}{ICON_OK}{COLOR_RESET}" if ICON_OK == "✔" else f"{COLOR_GREEN}0{COLOR_RESET}")
            vuls_cell = TerminalTextFormatter.pad_string(styled_vuls, w_vuls, align="center")
            print(f"{t['vertical']}{name_cell}{t['vertical']}{type_cell}{t['vertical']}{dec_cell}{t['vertical']}{inst_cell}{t['vertical']}{latest_cell}{t['vertical']}{status_cell}{t['vertical']}{vuls_cell}{t['vertical']}")
        else:
            print(f"{t['vertical']}{name_cell}{t['vertical']}{type_cell}{t['vertical']}{dec_cell}{t['vertical']}{inst_cell}{t['vertical']}{latest_cell}{t['vertical']}{status_cell}{t['vertical']}")

    print(border_bot)
    _print_table_notes_and_diffs(filtered_results)
    if vuls_enabled:
        _print_table_vulnerabilities(filtered_results)


def print_summary(results, elapsed_time, vuls_enabled=False, projects_count=None):
    """Prints checks run count and categorization breakdown."""
    total = len(results)
    # Optimization: Use sets for O(1) membership lookups
    up_to_date = sum(1 for r in results if r["status"] in {"up-to-date", "local"})
    # Optimization: Use sets for O(1) membership lookups
    patch = sum(1 for r in results if r["status"] in {"patch", "patch-major"})
    # Optimization: Use sets for O(1) membership lookups
    minor = sum(1 for r in results if r["status"] in {"minor", "minor-major"})
    major = sum(
        # Optimization: Use sets for O(1) membership lookups
        1
        for r in results
        if r["status"] in {"major", "minor-major", "patch-major"}
    )
    deprecated = sum(1 for r in results if r["deprecated"])
    errors = sum(1 for r in results if r["status"] == "error")

    outdated_total = sum(
        1
        for r in results
        # Optimization: Use sets for O(1) membership lookups
        if r["status"] in {"patch", "minor", "major", "minor-major", "patch-major"}
    )

    print(f"\n{COLOR_BOLD}{COLOR_CYAN}Summary Report:{COLOR_RESET}")
    if projects_count is not None:
        print(f"  Projects:    {COLOR_BOLD}{projects_count}{COLOR_RESET} scanned")
    print(f"  Checked:     {total} packages in {elapsed_time:.2f}s")
    print(f"  Up-to-date:  {COLOR_GREEN}{up_to_date}{COLOR_RESET}")
    print(
        f"  Outdated:    {COLOR_YELLOW}{outdated_total}{COLOR_RESET} (Patch: {COLOR_CYAN}{patch}{COLOR_RESET}, Minor: {COLOR_YELLOW}{minor}{COLOR_RESET}, Major: {COLOR_RED}{major}{COLOR_RESET})"
    )
    if deprecated > 0:
        print(f"  Deprecated:  {COLOR_MAGENTA}{deprecated}{COLOR_RESET}")
    if errors > 0:
        print(f"  Errors:      {COLOR_RED}{errors}{COLOR_RESET}")

    if vuls_enabled:
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
        vuln_pkg_count = sum(1 for r in results if r.get("vulnerabilities"))
        suppressed_vulns = sum(
            len(r.get("suppressed_vulnerabilities", [])) for r in results
        )
        malicious_count = sum(
            1
            for r in results
            for v in r.get("vulnerabilities", [])
            if get_severity_level(v) == "malicious"
        )
        if total_vulns > 0:
            print(
                f"  Sec Vulnerabilities: {COLOR_RED}{COLOR_BOLD}{total_vulns}{COLOR_RESET} (in {vuln_pkg_count} packages)"
            )
        else:
            print(f"  Sec Vulnerabilities: {COLOR_GREEN}0{COLOR_RESET}")
        if malicious_count > 0:
            print(
                f"  Malicious Code:      {COLOR_RED}{COLOR_BOLD}{malicious_count}{COLOR_RESET}"
            )
        if suppressed_vulns > 0:
            print(f"  Suppressed Alerts:   {COLOR_GRAY}{suppressed_vulns}{COLOR_RESET}")
    print()


def export_json_report(results, filepath):
    """Exports results as raw JSON data."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(
            f"{COLOR_GREEN}{ICON_OK} JSON report successfully exported to {filepath}{COLOR_RESET}"
        )
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to export JSON report: {e}{COLOR_RESET}")


def generate_sarif_run(results):
    """Generates a SARIF run object from results."""
    # Cache for reading manifest file lines to avoid redundant disk I/O
    manifest_lines_cache = {}

    run = {
        "tool": {
            "driver": {
                "name": "Kevlar CheckDeps",
                "version": VERSION,
                "informationUri": "https://kevlar-checkdeps.dev",
                "rules": [],
            }
        },
        "results": [],
    }

    sarif_results = run["results"]
    rules_map = {}

    for r in results:
        name = r.get("name")
        installed = r.get("installed")
        declared = r.get("declared")
        status = r.get("status")
        deprecated = r.get("deprecated")
        tech = r.get("technology")
        error_msg = r.get("error")

        # Determine manifest file path and line number
        manifest_path = None
        line_number = 1

        rem = r.get("remediation")
        if rem and isinstance(rem, dict):
            manifest_path = rem.get("manifest_path")
            line_number = rem.get("line_number") or 1

        if not manifest_path:
            project_path = r.get("project_path") or "."
            if tech:
                manifest_files = find_manifest_files(project_path, tech)
                if manifest_files:
                    found_line = False
                    for path in manifest_files:
                        if path not in manifest_lines_cache:
                            if os.path.exists(path):
                                try:
                                    with open(
                                        path, "r", encoding="utf-8", errors="ignore"
                                    ) as f:
                                        manifest_lines_cache[path] = f.readlines()
                                except Exception:
                                    manifest_lines_cache[path] = []
                            else:
                                manifest_lines_cache[path] = []

                        lines = manifest_lines_cache[path]
                        best_score = -1
                        for idx, line in enumerate(lines):
                            if match_line_for_dependency(line, name, tech):
                                score = 1
                                if declared:
                                    ver_digits = re.search(r"\d+\.\d+", str(declared))
                                    if (
                                        ver_digits
                                        and ver_digits.group(0) in line
                                        or str(declared).strip() in line
                                    ):
                                        score = 2
                                if score > best_score:
                                    best_score = score
                                    manifest_path = path
                                    line_number = idx + 1
                                    if score == 2:
                                        found_line = True
                                        break
                        if found_line:
                            break
                    if not manifest_path:
                        manifest_path = manifest_files[0]

        # Standardize relative path for URI field (using forward slashes)
        rel_uri = "unknown_manifest"
        if manifest_path:
            try:
                rel_uri = os.path.relpath(manifest_path).replace("\\", "/")
            except Exception:
                rel_uri = str(manifest_path).replace("\\", "/")

        # Helper to create locations array
        def make_locations(uri, line):
            return [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line, "startColumn": 1},
                    }
                }
            ]

        # 1. Map Vulnerabilities
        vulns = r.get("vulnerabilities", [])
        for vuln in vulns:
            vuln_id = vuln.get("id") or "KEVLAR-VULN-UNKNOWN"
            summary = vuln.get("summary") or "Security vulnerability detected"
            details = vuln.get("details") or ""
            severity = get_severity_level(vuln)

            # Severity level mapping for SARIF:
            # critical/high -> error, medium -> warning, low/unknown -> note
            if severity in {"malicious", "critical", "high"}:
                sarif_level = "error"
            elif severity == "medium":
                sarif_level = "warning"
            else:
                sarif_level = "note"

            msg_text = f"Security Vulnerability: package '{name}' (version {installed}) has vulnerability {vuln_id}. Summary: {summary}"
            if details:
                msg_text += f"\nDetails: {details}"

            sarif_results.append(
                {
                    "ruleId": vuln_id,
                    "message": {"text": msg_text},
                    "level": sarif_level,
                    "locations": make_locations(rel_uri, line_number),
                    "properties": {
                        "packageName": name,
                        "installedVersion": installed,
                        "declaredConstraint": declared,
                        "technology": tech,
                        "vulnerabilityDetails": vuln,
                    },
                }
            )

            # Track in tool rules
            if vuln_id not in rules_map:
                rules_map[vuln_id] = {
                    "id": vuln_id,
                    "shortDescription": {"text": f"Vulnerability {vuln_id} in {name}"},
                }

        # 2. Map Configuration Drift (status == "error" and error starts with "Configuration Drift")
        is_config_drift = False
        if (
            status == "error"
            and error_msg
            and error_msg.startswith("Configuration Drift")
        ):
            is_config_drift = True
            rule_id = "KEVLAR-CONFIG-DRIFT"
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "message": {"text": error_msg},
                    "level": "error",
                    "locations": make_locations(rel_uri, line_number),
                    "properties": {
                        "packageName": name,
                        "installedVersion": installed,
                        "declaredConstraint": declared,
                        "technology": tech,
                    },
                }
            )
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": "Installed version of dependency violates declared constraint (Configuration Drift)"
                    },
                }

        # 3. Map Outdated Dependency (status in {"major", "minor", "patch"} and not is_config_drift)
        if status in {"major", "minor", "patch"} and not is_config_drift:
            rule_id = "KEVLAR-OUTDATED-DEPENDENCY"
            latest = r.get("latest") or "unknown"

            if status == "major":
                sarif_level = "error"
            elif status == "minor":
                sarif_level = "warning"
            else:
                sarif_level = "note"

            msg_text = f"Outdated dependency: package '{name}' (version {installed}) is behind latest version '{latest}' ({status} update available)."

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "message": {"text": msg_text},
                    "level": sarif_level,
                    "locations": make_locations(rel_uri, line_number),
                    "properties": {
                        "packageName": name,
                        "installedVersion": installed,
                        "latestVersion": latest,
                        "declaredConstraint": declared,
                        "technology": tech,
                        "updateType": status,
                    },
                }
            )
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": "Package version is outdated"},
                }

        # 4. Map Deprecation
        if deprecated:
            rule_id = "KEVLAR-DEPRECATED-PACKAGE"
            dep_msg = str(deprecated)

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "message": {"text": f"Deprecated package '{name}': {dep_msg}"},
                    "level": "warning",
                    "locations": make_locations(rel_uri, line_number),
                    "properties": {
                        "packageName": name,
                        "installedVersion": installed,
                        "technology": tech,
                    },
                }
            )
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": "Package is deprecated"},
                }

    # Set rules
    run["tool"]["driver"]["rules"] = list(rules_map.values())
    return run


def export_sarif_report(results, filepath):
    """Exports results as a SARIF v2.1.0 JSON document."""
    try:
        run = generate_sarif_run(results)
        sarif_log = {
            "$schema": "https://schemastore.org/json/schema/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [run],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2)
        print(
            f"{COLOR_GREEN}{ICON_OK} SARIF report successfully exported to {filepath}{COLOR_RESET}"
        )
    except Exception as e:
        print(
            f"{COLOR_RED}{ICON_ERROR} Failed to export SARIF report: {e}{COLOR_RESET}"
        )


def export_markdown_report(results, pkg_data, filepath, vuls_enabled=False):
    """Exports results as a clean Markdown document."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# Dependency Status Report\n")
            f.write(
                "[GitHub Repository](https://github.com/brunoevn/kevlar-checkdeps)\n\n"
            )
            f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Write summary
            total = len(results)
            up_to_date = sum(
                # Optimization: Use sets for O(1) membership lookups
                1
                for r in results
                if r["status"] in {"up-to-date", "local"}
            )
            # Optimization: Use sets for O(1) membership lookups
            patch = sum(1 for r in results if r["status"] in {"patch", "patch-major"})
            # Optimization: Use sets for O(1) membership lookups
            minor = sum(1 for r in results if r["status"] in {"minor", "minor-major"})
            major = sum(
                1
                for r in results
                if r["status"] in {"major", "minor-major", "patch-major"}
            )
            deprecated = sum(1 for r in results if r["deprecated"])
            errors = sum(1 for r in results if r["status"] == "error")
            outdated_total = sum(
                1
                for r in results
                if r["status"]
                in {"patch", "minor", "major", "minor-major", "patch-major"}
            )

            f.write("## Summary\n\n")
            f.write(f"- **Total Checked**: {total}\n")
            f.write(f"- **Up-to-date**: {up_to_date}\n")
            f.write(
                f"- **Outdated**: {outdated_total} (Patch: {patch}, Minor: {minor}, Major: {major})\n"
            )
            if deprecated:
                f.write(f"- **Deprecated**: {deprecated}\n")
            if errors:
                f.write(f"- **Errors**: {errors}\n")

            if vuls_enabled:
                total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
                vuln_pkg_count = sum(1 for r in results if r.get("vulnerabilities"))
                suppressed_vulns = sum(
                    len(r.get("suppressed_vulnerabilities", [])) for r in results
                )
                f.write(
                    f"- **Security Vulnerabilities**: {total_vulns} found in {vuln_pkg_count} packages\n"
                )
                if suppressed_vulns > 0:
                    f.write(f"- **Suppressed Alerts**: {suppressed_vulns}\n")
            f.write("\n")

            # Write table
            f.write("## Dependency Details\n\n")
            if vuls_enabled:
                f.write(
                    "| Package | Type | Declared | Installed | Latest | Status | Vuls | Note |\n"
                )
                f.write("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
            else:
                f.write(
                    "| Package | Type | Declared | Installed | Latest | Status | Note |\n"
                )
                f.write("| --- | --- | --- | --- | --- | --- | --- |\n")

            for r in results:
                dep_type = "Transitive"
                if r.get("is_engine", False):
                    dep_type = "Engine"
                elif pkg_data:
                    if r["name"] in pkg_data.get("dependencies", {}):
                        dep_type = "Direct"
                    elif r["name"] in pkg_data.get("devDependencies", {}):
                        dep_type = "Dev"

                if (
                    dep_type == "Transitive"
                    and r.get("required_by")
                    and not r.get("is_engine", False)
                ):
                    dep_type = f"Transitive (via {', '.join(r['required_by'])})"

                status_str = r["status"]
                if status_str == "up-to-date":
                    status_display = "✅ Up-to-date"
                elif status_str == "patch":
                    status_display = "ℹ️ Patch Update"
                elif status_str == "minor":
                    status_display = "⚠️ Minor Update"
                elif status_str == "major":
                    status_display = "❌ Major Update"
                elif status_str == "error":
                    status_display = f"❓ Error ({r['error']})"
                elif status_str == "local":
                    status_display = "🔍 Verify Local"
                elif status_str == "minor-major":
                    status_display = "⚠️ Minor / ❌ Major Update"
                elif status_str == "patch-major":
                    status_display = "ℹ️ Patch / ❌ Major Update"

                notes_list = []
                if r["deprecated"]:
                    status_display = "🚫 Deprecated"
                    notes_list.append(f"Deprecation Warning: {r['deprecated']}")
                if r.get("missing_checksum"):
                    notes_list.append("⚠️ Missing integrity checksum in lockfile")
                elif r.get("weak_checksum"):
                    notes_list.append("⚠️ Weak checksum (SHA-1) in lockfile")

                if r.get("mismatch_checksum"):
                    notes_list.append(
                        "❌ **INTEGRITY MISMATCH!** Lockfile checksum does not match official registry checksum"
                    )

                note = " | ".join(notes_list)

                changelog_links = []
                if r.get("compare_url"):
                    changelog_links.append(f"[Compare Diff]({r['compare_url']})")
                if r.get("releases_url"):
                    changelog_links.append(f"[Release Notes]({r['releases_url']})")
                if changelog_links:
                    links_str = " | ".join(changelog_links)
                    if note:
                        note += f" ({links_str})"
                    else:
                        note = links_str

                if vuls_enabled:
                    vuls_count = len(r.get("vulnerabilities", []))
                    vuls_str = f"⚠️ **{vuls_count}**" if vuls_count > 0 else "✅"
                    f.write(
                        f"| `{r['name']}` | {dep_type} | `{r['declared'] or 'N/A'}` | `{r['installed'] or 'N/A'}` | `{r['latest'] or 'N/A'}` | {status_display} | {vuls_str} | {note} |\n"
                    )
                else:
                    f.write(
                        f"| `{r['name']}` | {dep_type} | `{r['declared'] or 'N/A'}` | `{r['installed'] or 'N/A'}` | `{r['latest'] or 'N/A'}` | {status_display} | {note} |\n"
                    )

            # Write detailed security section
            if vuls_enabled:
                vuls_list_total = []
                severity_order = {
                    "malicious": 5,
                    "critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                    "unknown": 0,
                }
                for r in results:
                    v_list = r.get("vulnerabilities", [])
                    if v_list:
                        sorted_v = sorted(
                            v_list,
                            key=lambda v: severity_order.get(get_severity_level(v), 0),
                            reverse=True,
                        )
                        vuls_list_total.append(
                            (
                                r["name"],
                                r["installed"],
                                sorted_v,
                                r.get("required_by", []),
                            )
                        )

                if vuls_list_total:
                    # Sort package groups by their maximum vulnerability severity descending, and alphabetically by package name ascending
                    vuls_list_total.sort(
                        key=lambda x: (
                            (
                                -max(
                                    severity_order.get(get_severity_level(v), 0)
                                    for v in x[2]
                                )
                                if x[2]
                                else 1
                            ),
                            x[0].lower(),
                        )
                    )
                    f.write("\n## Security Vulnerabilities Details\n\n")
                    for name, ver, v_list, required_by in vuls_list_total:
                        parent_suffix = (
                            f" (via {', '.join(required_by)})" if required_by else ""
                        )
                        f.write(
                            f"### `{name}@{ver}`{parent_suffix} ({len(v_list)} vulnerabilities)\n\n"
                        )
                        for vuln in v_list:
                            level = get_severity_level(vuln)
                            display_severity = (
                                "MALICIOUS CODE"
                                if level == "malicious"
                                else f"{level.upper()} - {vuln['severity']}"
                            )
                            f.write(
                                f"- **{vuln['id']}** [{display_severity}]: {vuln['summary']}\n"
                            )
                            if vuln.get("details"):
                                details_escaped = vuln["details"].replace("\n", "\n> ")
                                f.write(f"  > {details_escaped}\n\n")
                            else:
                                f.write("\n")

                # Write suppressed vulnerabilities if any exist
                suppressed_list_total = []
                for r in results:
                    s_list = r.get("suppressed_vulnerabilities", [])
                    if s_list:
                        suppressed_list_total.append(
                            (
                                r["name"],
                                r["installed"] if r["installed"] else r["declared"],
                                s_list,
                                r.get("required_by", []),
                            )
                        )

                if suppressed_list_total:
                    f.write("\n## Suppressed Vulnerabilities (Ignored)\n\n")
                    for name, ver, s_list, required_by in suppressed_list_total:
                        parent_suffix = (
                            f" (via {', '.join(required_by)})" if required_by else ""
                        )
                        f.write(
                            f"### `{name}@{ver}`{parent_suffix} ({len(s_list)} suppressed)\n\n"
                        )
                        for vuln in s_list:
                            f.write(f"- **{vuln['id']}**: {vuln['summary']}\n")
                            f.write(
                                f"  - **Reason**: {vuln.get('suppressed_reason', 'N/A')}\n"
                            )
                            f.write(
                                f"  - **Justification**: {vuln.get('justification', 'N/A')}\n"
                            )
                            f.write(
                                f"  - **Expires At**: {vuln.get('expires_at', 'N/A')}\n"
                            )
                            if vuln.get("approved_by"):
                                f.write(f"  - **Approved By**: {vuln['approved_by']}\n")
                            f.write("\n")

        print(
            f"{COLOR_GREEN}{ICON_OK} Markdown report successfully exported to {filepath}{COLOR_RESET}"
        )
    except Exception as e:
        print(
            f"{COLOR_RED}{ICON_ERROR} Failed to export Markdown report: {e}{COLOR_RESET}"
        )


def escape_html(text):
    """Safely escape HTML characters."""
    if text is None:
        return ""
    text_str = str(text)
    return (
        text_str.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def get_upgraded_constraint(declared_ver, latest_ver):
    """Synthesize upgraded constraint preserving prefixes like ^, ~, ==, >=."""
    if not declared_ver or not latest_ver:
        return latest_ver

    # Extract prefix, e.g., ^, ~, >=, ==, ~>
    match = RE_OPERATOR_PREFIX_MATCH.match(declared_ver.strip())
    if match:
        prefix = match.group(1)
        return prefix + latest_ver

    return latest_ver


def _match_npm_php(line_lower, pkg_lower):
    pattern = r'"' + re.escape(pkg_lower) + r'"\s*:'
    return re.search(pattern, line_lower) is not None


def _match_pip(line_lower, pkg_lower):
    extras = r"(\[[^\]]+\])?"
    pattern_req = (
        r"^\s*" + re.escape(pkg_lower) + extras + r'\s*(==|>=|<=|~=|!=|>|<|@|;|[\'"]|$)'
    )
    pattern_toml = r"^\s*" + re.escape(pkg_lower) + r"\s*=\s*"
    pattern_setup = (
        r'[\'"]' + re.escape(pkg_lower) + extras + r'([>=<!~^@;]+|[\'"]\s*[,\]])'
    )
    return (
        re.search(pattern_req, line_lower) is not None
        or re.search(pattern_toml, line_lower) is not None
        or re.search(pattern_setup, line_lower) is not None
    )


def _match_nuget(line_lower, pkg_lower):
    pattern = r'(include|update)\s*=\s*[\'"]' + re.escape(pkg_lower) + r'[\'"]'
    return re.search(pattern, line_lower) is not None


def _match_maven(line_lower, pkg_lower):
    parts = pkg_lower.split(":")
    artifact = parts[-1]
    pattern = r"<artifactid>\s*" + re.escape(artifact) + r"\s*</artifactid>"
    return re.search(pattern, line_lower) is not None


def _match_go(line_lower, pkg_lower):
    pattern = re.escape(pkg_lower) + r"\s+v\d+"
    return re.search(pattern, line_lower) is not None


def _match_rust(line_lower, pkg_lower):
    pattern_eq = r"^\s*" + re.escape(pkg_lower) + r"\s*=\s*"
    pattern_sec = (
        r"\[\s*(?:target\.[^\]]+\.)?(?:dependencies|dev-dependencies|build-dependencies)\."
        + re.escape(pkg_lower)
        + r"\s*\]"
    )
    return (
        re.search(pattern_eq, line_lower) is not None
        or re.search(pattern_sec, line_lower) is not None
    )


def _match_ruby(line_lower, pkg_lower):
    pattern = r'gem\s+[\'"]' + re.escape(pkg_lower) + r'[\'"]'
    return re.search(pattern, line_lower) is not None


def _match_gradle(line_lower, pkg_lower):
    parts = pkg_lower.split(":")
    if len(parts) > 1:
        group, name_part = parts[0], parts[1]
        pattern_build = re.escape(group) + r":" + re.escape(name_part)
        return re.search(pattern_build, line_lower) is not None
    else:
        pattern_toml = r"^\s*" + re.escape(pkg_lower) + r"\s*=\s*"
        pattern_name = r'name\s*=\s*[\'"]' + re.escape(pkg_lower) + r'[\'"]'
        return (
            re.search(pattern_toml, line_lower) is not None
            or re.search(pattern_name, line_lower) is not None
        )


MATCH_STRATEGIES = {
    "npm": _match_npm_php,
    "php": _match_npm_php,
    "pip": _match_pip,
    "nuget": _match_nuget,
    "maven": _match_maven,
    "go": _match_go,
    "rust": _match_rust,
    "ruby": _match_ruby,
    "gradle": _match_gradle,
}


def match_line_for_dependency(line, package_name, tech):
    """Checks if a manifest file line matches the given package dependency declaration."""
    line_lower = line.lower()
    pkg_lower = package_name.lower()

    strategy = MATCH_STRATEGIES.get(tech)
    if strategy:
        return strategy(line_lower, pkg_lower)
    return False


def find_manifest_files(project_path, technology):
    """Finds manifest files for the given technology in the project path."""
    manifest_files = []
    if os.path.isfile(project_path):
        return [project_path]

    if not os.path.exists(project_path):
        return []

    tech_patterns = {
        "npm": ["package.json"],
        "pip": ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"],
        "nuget": [".csproj", ".vbproj", ".fsproj", "Directory.Packages.props"],
        "php": ["composer.json"],
        "maven": ["pom.xml"],
        "go": ["go.mod"],
        "rust": ["Cargo.toml"],
        "ruby": ["Gemfile"],
        "gradle": ["build.gradle", "build.gradle.kts", "libs.versions.toml"],
    }

    patterns = tech_patterns.get(technology, [])
    if not patterns:
        return []

    ignored_dirs = {".git", "node_modules", "bin", "obj", ".gradle", "venv", ".venv"}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        for file in files:
            for pattern in patterns:
                if pattern.startswith("."):
                    if file.lower().endswith(pattern):
                        manifest_files.append(os.path.join(root, file))
                else:
                    if file == pattern:
                        manifest_files.append(os.path.join(root, file))

    if technology == "nuget":
        curr = os.path.abspath(project_path)
        if os.path.isfile(curr):
            curr = os.path.dirname(curr)
        for _ in range(10):
            props_file = os.path.join(curr, "Directory.Packages.props")
            if os.path.exists(props_file) and props_file not in manifest_files:
                manifest_files.append(props_file)
            parent = os.path.dirname(curr)
            if parent == curr:
                break
            curr = parent

    return manifest_files


def _find_target_version_line(lines, search_range, declared_ver, tech, package_name, fallback_idx):
    """Finds the line index and target text to replace in the manifest lines."""
    if declared_ver:
        for i in search_range:
            if declared_ver in lines[i]:
                return i, declared_ver

    if tech == "maven":
        for i in search_range:
            m = re.search(r"<version>\s*(.*?)\s*</version>", lines[i], re.IGNORECASE)
            if m:
                return i, m.group(1)
    elif tech == "gradle":
        for i in search_range:
            m_ref = re.search(r'version\.ref\s*=\s*["\']([^"\']+)["\']', lines[i])
            if m_ref:
                return i, m_ref.group(1)
            m_eq = re.search(r'version\s*=\s*["\']([^"\']+)["\']', lines[i])
            if m_eq:
                return i, m_eq.group(1)
            m_colon = re.search(r'version:\s*["\']([^"\']+)["\']', lines[i])
            if m_colon:
                return i, m_colon.group(1)
            if package_name:
                pattern = re.escape(package_name) + r':([^\'"]+)'
                m_str = re.search(pattern, lines[i])
                if m_str:
                    return i, m_str.group(1)
    elif tech == "nuget":
        for i in search_range:
            m = re.search(r'Version\s*=\s*["\']([^"\']+)["\']', lines[i], re.IGNORECASE)
            if m:
                return i, m.group(1)

    if declared_ver:
        ver_digits = RE_DECIMAL_VER.search(declared_ver)
        if ver_digits:
            ver_clean = ver_digits.group(0)
            for i in search_range:
                if ver_clean in lines[i]:
                    return i, ver_clean

    target_text = None
    ver_pattern = RE_DECIMAL_VER.search(lines[fallback_idx])
    if ver_pattern:
        target_text = ver_pattern.group(0)
    else:
        quotes_match = re.search(r'["\']([^"\']+)["\']', lines[fallback_idx])
        if quotes_match:
            quoted_vals = re.findall(r'["\']([^"\']+)["\']', lines[fallback_idx])
            if quoted_vals:
                target_text = quoted_vals[-1]

    return fallback_idx, target_text


def _resolve_property_placeholder(manifest_path, target_text, tech, lines, line_idx_to_change, declared_ver):
    """Resolves Maven/Gradle/NuGet property placeholders to concrete files and line numbers."""
    def _search_lines_for_property(lines_list, prop_name_val, tech_type):
        if tech_type in ("maven", "nuget"):
            pattern = r"<\s*" + re.escape(prop_name_val) + r"\s*>\s*(.*?)\s*<\s*/\s*" + re.escape(prop_name_val) + r"\s*>"
            for idx_p, line_p in enumerate(lines_list):
                m_p = re.search(pattern, line_p, re.IGNORECASE)
                if m_p:
                    return idx_p + 1, m_p.group(1)
        elif tech_type == "gradle":
            pattern = r"^\s*([a-zA-Z0-9_.-]+)?\s*" + re.escape(prop_name_val) + r'\s*=\s*["\']([^"\']+)["\']'
            for idx_p, line_p in enumerate(lines_list):
                m_p = re.search(pattern, line_p)
                if m_p:
                    return idx_p + 1, m_p.group(2)
        return None, None

    def find_property_definition(current_path, prop_name_val, tech_type):
        try:
            with open(current_path, "r", encoding="utf-8", errors="ignore") as f_p:
                lines_list = f_p.readlines()
        except Exception:
            return None, None, None

        line_idx_p, val_p = _search_lines_for_property(lines_list, prop_name_val, tech_type)
        if line_idx_p is not None:
            return current_path, line_idx_p, val_p

        if tech_type == "maven":
            curr_dir_p = current_path
            for _ in range(5):
                curr_dir_p = os.path.dirname(curr_dir_p)
                parent_dir_p = os.path.dirname(curr_dir_p)
                if parent_dir_p == curr_dir_p:
                    break
                parent_pom = os.path.join(parent_dir_p, "pom.xml")
                if os.path.exists(parent_pom):
                    try:
                        with open(parent_pom, "r", encoding="utf-8", errors="ignore") as f_p:
                            parent_lines = f_p.readlines()
                        line_idx_p, val_p = _search_lines_for_property(parent_lines, prop_name_val, tech_type)
                        if line_idx_p is not None:
                            return parent_pom, line_idx_p, val_p
                    except (OSError, UnicodeDecodeError):
                        pass
                    curr_dir_p = parent_pom
                else:
                    break
        return None, None, None

    is_placeholder = False
    prop_name = None
    if tech == "maven":
        m = re.match(r"^\s*\$\SafeWriter?\{\s*(.*?)\s*\}\s*$", target_text) if hasattr(re, 'match') else None
        m = re.match(r"^\s*\$\{\s*(.*?)\s*\}\s*$", target_text)
        if m:
            is_placeholder = True
            prop_name = m.group(1)
    elif tech == "nuget":
        m = re.match(r"^\s*\$\(\s*(.*?)\s*\)\s*$", target_text)
        if m:
            is_placeholder = True
            prop_name = m.group(1)
    elif tech == "gradle":
        is_toml_ref = "version.ref" in lines[line_idx_to_change]
        if is_toml_ref:
            is_placeholder = True
            prop_name = target_text
        elif target_text.startswith("$"):
            is_placeholder = True
            prop_name = target_text[1:]

    new_path = manifest_path
    new_idx = line_idx_to_change
    resolved_ver = target_text
    new_lines = lines

    if is_placeholder and prop_name:
        resolved_path, resolved_line_idx, current_val = find_property_definition(manifest_path, prop_name, tech)
        if resolved_path and resolved_line_idx:
            new_path = resolved_path
            try:
                with open(new_path, "r", encoding="utf-8", errors="ignore") as f:
                    new_lines = f.readlines()
                new_idx = resolved_line_idx - 1
                resolved_ver = current_val
            except (OSError, UnicodeDecodeError):
                pass

    if declared_ver and resolved_ver:
        is_val_placeholder = (
            (tech == "maven" and "${" in resolved_ver) or
            (tech == "nuget" and "$(" in resolved_ver) or
            (tech == "gradle" and "$" in resolved_ver)
        )
        if not is_val_placeholder:
            def clean_ver(v):
                v = v.strip().lower().removeprefix("v")
                return RE_OPERATOR_PREFIX.sub("", v)

            def is_version_compatible(v1, v2):
                c1, c2 = clean_ver(v1), clean_ver(v2)
                if not c1 or not c2 or c1 == c2 or c1.startswith(c2) or c2.startswith(c1):
                    return True
                m1, m2 = RE_NUM_START.match(c1), RE_NUM_START.match(c2)
                return bool(m1 and m2 and m1.group(1) == m2.group(1))

            if not is_version_compatible(declared_ver, resolved_ver):
                return None, None, None, None

    return new_path, new_idx, resolved_ver, new_lines


def generate_remediation_diff(manifest_path, line_index, declared_ver, latest_ver, tech, package_name=None):
    """Generates remediation diff showing current vs suggested change."""
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None

    idx = line_index - 1
    if idx < 0 or idx >= len(lines):
        return None

    search_range = range(idx, min(idx + 4, len(lines)))
    line_idx_to_change, target_text = _find_target_version_line(lines, search_range, declared_ver, tech, package_name, idx)

    if (
        target_text
        and package_name
        and target_text.lower().strip() == package_name.lower().strip()
    ):
        target_text = None

    if not target_text:
        return None

    res_path, res_idx, res_text, res_lines = _resolve_property_placeholder(
        manifest_path, target_text, tech, lines, line_idx_to_change, declared_ver
    )
    if res_path is None:
        return None

    manifest_path = res_path
    line_idx_to_change = res_idx
    target_text = res_text
    lines = res_lines

    match_prefix = ""
    match_version = target_text or ""
    if target_text:
        match_opt = RE_OPERATOR_PREFIX_MATCH.match(target_text.strip())
        if match_opt:
            match_prefix = match_opt.group(1)
            match_version = match_opt.group(2)

    effective_prefix = match_prefix
    if RE_OPERATOR_START.match(latest_ver.strip()):
        effective_prefix = ""

    upgraded_str = effective_prefix + latest_ver

    def _clean_v(v):
        if not v:
            return ""
        v = str(v).strip().lower().removeprefix("v")
        return RE_OPERATOR_PREFIX.sub("", v)

    if target_text and latest_ver and _clean_v(target_text) == _clean_v(latest_ver):
        return None

    start_ctx = max(0, line_idx_to_change - 2)
    end_ctx = min(len(lines), line_idx_to_change + 3)

    current_block = []
    suggested_block = []

    for i in range(start_ctx, end_ctx):
        orig_line = lines[i].rstrip("\r\n")
        line_num = i + 1

        if i == line_idx_to_change:
            escaped_orig = escape_html(orig_line)
            if target_text and target_text in orig_line:
                escaped_target = escape_html(target_text)
                html_orig = escaped_orig.replace(
                    escaped_target,
                    f'<span class="diff-remove-chunk">{escaped_target}</span>',
                )
                new_line = orig_line.replace(target_text, upgraded_str)
            else:
                html_orig = escaped_orig
                new_line = orig_line + f" -> {latest_ver}"

            escaped_new = escape_html(new_line)
            escaped_upgraded = escape_html(upgraded_str)

            if upgraded_str in new_line:
                html_new = escaped_new.replace(
                    escaped_upgraded,
                    f'<span class="diff-add-chunk">{escaped_upgraded}</span>',
                )
            else:
                html_new = escaped_new

            current_block.append({"line_num": line_num, "html": html_orig, "is_changed": True})
            suggested_block.append({"line_num": line_num, "html": html_new, "is_changed": True})
        else:
            escaped_orig = escape_html(orig_line)
            current_block.append({"line_num": line_num, "html": escaped_orig, "is_changed": False})
            suggested_block.append({"line_num": line_num, "html": escaped_orig, "is_changed": False})

    return {
        "manifest_path": manifest_path,
        "line_number": line_idx_to_change + 1,
        "current_code": current_block,
        "suggested_code": suggested_block,
    }


def generate_addition_remediation_diff(manifest_path, package_name, target_ver, tech):
    """Generates remediation diff showing an addition to the manifest file when missing."""
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None

    if not lines:
        return None

    insert_line_idx = None
    indent = "    "
    line_to_add = ""

    raw_ver = str(target_ver).strip()
    clean_numeric = raw_ver.lstrip("^~>=<! v")

    if tech in {"npm", "pnpm", "yarn"}:
        clean_target = f"^{clean_numeric}" if not RE_OPERATOR_START.match(raw_ver) else raw_ver
        deps_match_idx = None
        dev_deps_match_idx = None
        root_open_idx = None
        for idx, line in enumerate(lines):
            if re.search(r'"dependencies"\s*:\s*\{', line):
                deps_match_idx = idx
                break
            elif re.search(r'"devDependencies"\s*:\s*\{', line):
                dev_deps_match_idx = idx
            elif root_open_idx is None and "{" in line:
                root_open_idx = idx

        if deps_match_idx is not None:
            insert_line_idx = deps_match_idx + 1
            line_to_add = f'{indent}"{package_name}": "{clean_target}",'
        elif dev_deps_match_idx is not None:
            insert_line_idx = dev_deps_match_idx + 1
            line_to_add = f'{indent}"{package_name}": "{clean_target}",'
        elif root_open_idx is not None:
            insert_line_idx = root_open_idx + 1
            line_to_add = f'{indent}"dependencies": {{\n{indent}  "{package_name}": "{clean_target}"\n{indent}}},'
    elif tech == "php":
        clean_target = f"^{clean_numeric}" if not RE_OPERATOR_START.match(raw_ver) else raw_ver
        deps_match_idx = None
        for idx, line in enumerate(lines):
            if re.search(r'"require"\s*:\s*\{', line):
                deps_match_idx = idx
                break
        if deps_match_idx is not None:
            insert_line_idx = deps_match_idx + 1
            line_to_add = f'{indent}"{package_name}": "{clean_target}",'
        else:
            insert_line_idx = len(lines)
            line_to_add = f'{indent}"require": {{\n{indent}  "{package_name}": "{clean_target}"\n{indent}}},'
    elif tech == "go":
        go_ver = f"v{clean_numeric}" if not raw_ver.startswith("v") else raw_ver
        go_ver = RE_OPERATOR_PREFIX.sub("", go_ver)
        req_open_idx = None
        req_close_idx = None
        for idx, line in enumerate(lines):
            if re.match(r"^\s*require\s*\(", line):
                req_open_idx = idx
            elif req_open_idx is not None and re.match(r"^\s*\)", line):
                req_close_idx = idx
                break
        if req_close_idx is not None:
            insert_line_idx = req_close_idx
            line_to_add = f"\t{package_name} {go_ver}"
        else:
            insert_line_idx = len(lines)
            line_to_add = f"require {package_name} {go_ver}"
    elif tech == "pip":
        insert_line_idx = len(lines)
        line_to_add = f"{package_name}>={clean_numeric}"
    elif tech == "rust":
        dep_sec_idx = None
        for idx, line in enumerate(lines):
            if re.search(r"^\[dependencies\]", line.strip()):
                dep_sec_idx = idx
                break
        if dep_sec_idx is not None:
            insert_line_idx = dep_sec_idx + 1
            line_to_add = f'{package_name} = "{clean_numeric}"'
        else:
            insert_line_idx = len(lines)
            line_to_add = f'\n[dependencies]\n{package_name} = "{clean_numeric}"'
    elif tech == "ruby":
        insert_line_idx = len(lines)
        line_to_add = f"gem '{package_name}', '~> {clean_numeric}'"
    elif tech == "nuget":
        insert_line_idx = len(lines)
        if "Directory.Packages.props" in manifest_path:
            line_to_add = f'  <PackageVersion Include="{package_name}" Version="{clean_numeric}" />'
        else:
            line_to_add = f'  <PackageReference Include="{package_name}" Version="{clean_numeric}" />'
    else:
        insert_line_idx = len(lines)
        line_to_add = f"{package_name}: {clean_numeric}"

    start_ctx = max(0, insert_line_idx - 2)
    end_ctx = min(len(lines), insert_line_idx + 3)

    current_block = []
    suggested_block = []

    for i in range(start_ctx, end_ctx):
        line_num = i + 1
        orig_line = lines[i].rstrip("\r\n")
        escaped_orig = escape_html(orig_line)

        if i == insert_line_idx:
            escaped_add = escape_html(line_to_add)
            suggested_block.append(
                {
                    "line_num": "+",
                    "html": f'<span class="diff-add-chunk">{escaped_add}</span>',
                    "is_changed": True,
                }
            )

        current_block.append(
            {"line_num": line_num, "html": escaped_orig, "is_changed": False}
        )
        suggested_block.append(
            {"line_num": line_num, "html": escaped_orig, "is_changed": False}
        )

    if insert_line_idx >= len(lines):
        escaped_add = escape_html(line_to_add)
        suggested_block.append(
            {
                "line_num": "+",
                "html": f'<span class="diff-add-chunk">{escaped_add}</span>',
                "is_changed": True,
            }
        )

    return {
        "manifest_path": manifest_path,
        "line_number": insert_line_idx + 1,
        "current_code": current_block,
        "suggested_code": suggested_block,
        "is_addition": True,
    }


def generate_override_remediation_diff(manifest_path, package_name, target_ver, tech):
    """Generates remediation diff for forcing a transitive dependency override in manifest_path."""
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None

    if not lines:
        return None

    raw_ver = str(target_ver).strip()
    clean_numeric = raw_ver.lstrip("^~>=<! v")
    indent = "    "
    insert_line_idx = None
    line_to_add = ""

    if tech in {"npm", "pnpm"}:
        clean_target = f"^{clean_numeric}" if not RE_OPERATOR_START.match(raw_ver) else raw_ver
        overrides_line_idx = None
        for idx, line in enumerate(lines):
            if re.search(r'"overrides"\s*:\s*\{', line):
                overrides_line_idx = idx
                break

        if overrides_line_idx is not None:
            insert_line_idx = overrides_line_idx + 1
            line_to_add = f'{indent}  "{package_name}": "{clean_target}",'
        else:
            root_open_idx = None
            for idx, line in enumerate(lines):
                if "{" in line:
                    root_open_idx = idx
                    break
            insert_line_idx = (root_open_idx + 1) if root_open_idx is not None else 1
            line_to_add = f'{indent}"overrides": {{\n{indent}  "{package_name}": "{clean_target}"\n{indent}}},'
    elif tech == "yarn":
        clean_target = f"^{clean_numeric}" if not RE_OPERATOR_START.match(raw_ver) else raw_ver
        resolutions_line_idx = None
        for idx, line in enumerate(lines):
            if re.search(r'"resolutions"\s*:\s*\{', line):
                resolutions_line_idx = idx
                break
        if resolutions_line_idx is not None:
            insert_line_idx = resolutions_line_idx + 1
            line_to_add = f'{indent}  "{package_name}": "{clean_target}",'
        else:
            root_open_idx = None
            for idx, line in enumerate(lines):
                if "{" in line:
                    root_open_idx = idx
                    break
            insert_line_idx = (root_open_idx + 1) if root_open_idx is not None else 1
            line_to_add = f'{indent}"resolutions": {{\n{indent}  "{package_name}": "{clean_target}"\n{indent}}},'
    elif tech == "go":
        go_ver = f"v{clean_numeric}" if not raw_ver.startswith("v") else raw_ver
        go_ver = RE_OPERATOR_PREFIX.sub("", go_ver)
        insert_line_idx = len(lines)
        line_to_add = f"replace {package_name} => {package_name} {go_ver}"
    elif tech == "rust":
        patch_sec_idx = None
        for idx, line in enumerate(lines):
            if re.search(r"^\[patch\.crates-io\]", line.strip()):
                patch_sec_idx = idx
                break
        if patch_sec_idx is not None:
            insert_line_idx = patch_sec_idx + 1
            line_to_add = f'{package_name} = "{clean_numeric}"'
        else:
            insert_line_idx = len(lines)
            line_to_add = f'\n[patch.crates-io]\n{package_name} = "{clean_numeric}"'
    else:
        return generate_addition_remediation_diff(
            manifest_path, package_name, target_ver, tech
        )

    start_ctx = max(0, insert_line_idx - 2)
    end_ctx = min(len(lines), insert_line_idx + 3)

    current_block = []
    suggested_block = []

    for i in range(start_ctx, end_ctx):
        line_num = i + 1
        orig_line = lines[i].rstrip("\r\n")
        escaped_orig = escape_html(orig_line)

        if i == insert_line_idx:
            escaped_add = escape_html(line_to_add)
            suggested_block.append(
                {
                    "line_num": "+",
                    "html": f'<span class="diff-add-chunk">{escaped_add}</span>',
                    "is_changed": True,
                }
            )

        current_block.append(
            {"line_num": line_num, "html": escaped_orig, "is_changed": False}
        )
        suggested_block.append(
            {"line_num": line_num, "html": escaped_orig, "is_changed": False}
        )

    if insert_line_idx >= len(lines):
        escaped_add = escape_html(line_to_add)
        suggested_block.append(
            {
                "line_num": "+",
                "html": f'<span class="diff-add-chunk">{escaped_add}</span>',
                "is_changed": True,
            }
        )

    return {
        "manifest_path": manifest_path,
        "line_number": insert_line_idx + 1,
        "current_code": current_block,
        "suggested_code": suggested_block,
        "is_addition": True,
    }


def format_remediation_option_label(ver_str: str) -> str:
    """Formats a version/constraint string into a user-friendly tab label.
    Examples:
        ">=24.0.0" -> "Version 24"
        ">=26.0.0" -> "Version 26"
        ">=24.0.0 or >=26.0.0" -> "Version 24 o 26"
    """
    if not ver_str:
        return ""

    def _clean_single_ver(s: str) -> str:
        s = s.strip()
        m = re.search(r"(?:>=|>|<=|<|~|\^|v)?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
        if m:
            major = m.group(1)
            minor = m.group(2)
            patch = m.group(3)
            if (not minor or minor == "0") and (not patch or patch == "0"):
                return major
            elif minor and patch:
                return f"{major}.{minor}.{patch}"
            elif minor:
                return f"{major}.{minor}"
            return major
        return s.lstrip("v>=").strip()

    if " or " in ver_str:
        parts = [p.strip() for p in ver_str.split(" or ") if p.strip()]
        clean_parts = [_clean_single_ver(p) for p in parts]
        return f"Version {' o '.join(clean_parts)}"
    else:
        clean_v = _clean_single_ver(ver_str)
        return f"Version {clean_v}"


def _clean_version_str(v):
    if not v:
        return ""
    v = str(v).strip().lower().removeprefix("v")
    return RE_OPERATOR_PREFIX.sub("", v)


def _populate_direct_strategies(r, manifest_path, found_line_idx, name, declared, tech, latest_patch, latest_sm, latest_abs):
    direct_options = []
    target_string = latest_abs or (r.get("latest") if r.get("name") == name else "") or ""
    if " or " in target_string:
        parts = [p.strip() for p in target_string.split(" or ") if p.strip()]
        if len(parts) >= 2:
            for p in parts:
                diff_p = (
                    generate_remediation_diff(manifest_path, found_line_idx, declared, p, tech, name)
                    if found_line_idx
                    else generate_addition_remediation_diff(manifest_path, name, p, tech)
                )
                if diff_p:
                    direct_options.append({
                        "id": f"option_{p}",
                        "label": format_remediation_option_label(p),
                        "badge": "Option",
                        "badge_class": "v-chip-safe",
                        "diff": diff_p,
                    })
            diff_comb = (
                generate_remediation_diff(manifest_path, found_line_idx, declared, target_string, tech, name)
                if found_line_idx
                else generate_addition_remediation_diff(manifest_path, name, target_string, tech)
            )
            if diff_comb:
                direct_options.append({
                    "id": f"option_{target_string}",
                    "label": format_remediation_option_label(target_string),
                    "badge": "Option",
                    "badge_class": "v-chip-major",
                    "diff": diff_comb,
                })

    if latest_patch:
        diff_patch = (
            generate_remediation_diff(manifest_path, found_line_idx, declared, latest_patch, tech, name)
            if found_line_idx
            else generate_addition_remediation_diff(manifest_path, name, latest_patch, tech)
        )
        if diff_patch:
            direct_options.append({
                "id": "patch",
                "label": f"Patch: v{_clean_version_str(latest_patch)}",
                "badge": "Patch / Bugfix",
                "badge_class": "v-chip-ok",
                "diff": diff_patch,
            })

    if latest_sm:
        diff_sm = (
            generate_remediation_diff(manifest_path, found_line_idx, declared, latest_sm, tech, name)
            if found_line_idx
            else generate_addition_remediation_diff(manifest_path, name, latest_sm, tech)
        )
        if diff_sm:
            direct_options.append({
                "id": "minor",
                "label": f"Minor: v{_clean_version_str(latest_sm)}",
                "badge": "Minor / Feature",
                "badge_class": "v-chip-safe",
                "diff": diff_sm,
            })

    if latest_abs and " or " not in str(latest_abs):
        diff_abs = (
            generate_remediation_diff(manifest_path, found_line_idx, declared, latest_abs, tech, name)
            if found_line_idx
            else generate_addition_remediation_diff(manifest_path, name, latest_abs, tech)
        )
        if diff_abs:
            direct_options.append({
                "id": "major",
                "label": f"Major: v{_clean_version_str(latest_abs)}",
                "badge": "Major / Breaking",
                "badge_class": "v-chip-major",
                "diff": diff_abs,
            })

    if direct_options:
        return [{
            "id": "direct_upgrade",
            "title": f"Update Dependency ({name})" if r.get("dep_type") == "Transitive" else f"Update Direct Dependency ({name})",
            "description": f"Updates '{name}' in manifest file.",
            "is_recommended": True,
            "options": direct_options,
        }]
    return []


def _populate_parent_strategies(r, results, manifest_path, lines, tech, name, get_line_idx_fn):
    strategies = []
    if not r.get("required_by"):
        return strategies

    for parent_name in r.get("required_by", []):
        parent_candidate = next(
            (
                item
                for item in results
                if item.get("name") == parent_name
                and item.get("project_path") == r.get("project_path")
            ),
            None,
        )
        if not parent_candidate:
            continue

        parent_line_idx = get_line_idx_fn(manifest_path, lines, parent_name, tech, parent_candidate.get("declared"), False)
        if parent_line_idx is None:
            continue

        p_name = parent_candidate.get("name")
        p_inst = parent_candidate.get("installed")
        p_clean_inst = p_inst[0] if (isinstance(p_inst, list) and p_inst) else p_inst
        p_decl = parent_candidate.get("declared")
        p_patch = parent_candidate.get("latest_patch")
        p_sm = parent_candidate.get("latest_same_major")
        p_abs = parent_candidate.get("latest_absolute") or parent_candidate.get("latest")

        p_clean_inst_v = _clean_version_str(p_clean_inst)
        p_clean_decl_v = _clean_version_str(p_decl)

        if p_patch and _clean_version_str(p_patch) in (p_clean_inst_v, p_clean_decl_v):
            p_patch = None
        if p_sm and (
            _clean_version_str(p_sm) in (p_clean_inst_v, p_clean_decl_v)
            or _clean_version_str(p_sm) == _clean_version_str(p_patch)
        ):
            p_sm = None
        if p_abs and (
            _clean_version_str(p_abs) in (p_clean_inst_v, p_clean_decl_v)
            or _clean_version_str(p_abs) == _clean_version_str(p_sm)
            or _clean_version_str(p_abs) == _clean_version_str(p_patch)
        ):
            p_abs = None

        parent_options = []
        if p_patch:
            p_diff = generate_remediation_diff(manifest_path, parent_line_idx, p_decl, p_patch, tech, p_name)
            if p_diff:
                parent_options.append({
                    "id": "patch",
                    "label": f"Patch {p_name}: v{_clean_version_str(p_patch)}",
                    "badge": "Patch / Bugfix",
                    "badge_class": "v-chip-ok",
                    "diff": p_diff,
                })
        if p_sm:
            p_diff = generate_remediation_diff(manifest_path, parent_line_idx, p_decl, p_sm, tech, p_name)
            if p_diff:
                parent_options.append({
                    "id": "minor",
                    "label": f"Minor {p_name}: v{_clean_version_str(p_sm)}",
                    "badge": "Minor / Feature",
                    "badge_class": "v-chip-safe",
                    "diff": p_diff,
                })
        if p_abs:
            p_diff = generate_remediation_diff(manifest_path, parent_line_idx, p_decl, p_abs, tech, p_name)
            if p_diff:
                parent_options.append({
                    "id": "major",
                    "label": f"Major {p_name}: v{_clean_version_str(p_abs)}",
                    "badge": "Major / Breaking",
                    "badge_class": "v-chip-major",
                    "diff": p_diff,
                })

        if parent_options:
            strategies.append({
                "id": "parent_upgrade",
                "title": f"Upgrade Parent Package ({p_name})",
                "description": f"Recommended. Upgrades parent package '{p_name}' which requires '{name}'.",
                "is_recommended": True,
                "options": parent_options,
            })
            break

    return strategies


def _populate_override_strategies(manifest_path, name, tech, latest_patch, latest_sm, latest_abs, clean_installed, has_prior_strategies):
    target_ver_str = latest_patch or latest_sm or latest_abs or clean_installed
    if not target_ver_str:
        return []

    ov_diff = generate_override_remediation_diff(manifest_path, name, target_ver_str, tech)
    if not ov_diff:
        return []

    ov_badge = "Patch" if target_ver_str == latest_patch else "Minor" if target_ver_str == latest_sm else "Major"
    ov_badge_class = "v-chip-ok" if ov_badge == "Patch" else "v-chip-safe" if ov_badge == "Minor" else "v-chip-major"

    return [{
        "id": "override",
        "title": f"Force Transitive Override ({name})",
        "description": f"Adds explicit override / resolution for '{name}' in manifest.",
        "is_recommended": not has_prior_strategies,
        "options": [{
            "id": "override",
            "label": f"Override {name}: v{_clean_version_str(target_ver_str)}",
            "badge": ov_badge,
            "badge_class": ov_badge_class,
            "diff": ov_diff,
        }],
    }]


def _build_final_remediation(strategies, manifest_missing):
    if not strategies:
        return None

    all_flat_options = []
    for st in strategies:
        all_flat_options.extend(st.get("options", []))

    remediation_safe = next((opt["diff"] for opt in all_flat_options if opt["id"] in {"patch", "minor"}), None)
    remediation_major = next((opt["diff"] for opt in all_flat_options if opt["id"] == "major"), None)
    remediation_options = (
        [{"label": opt["label"], "diff": opt["diff"]} for opt in all_flat_options]
        if all_flat_options
        else None
    )

    first_diff = all_flat_options[0]["diff"] if all_flat_options else None
    last_diff = all_flat_options[-1]["diff"] if all_flat_options else None

    return {
        "safe": remediation_safe or first_diff,
        "major": remediation_major or last_diff,
        "options": remediation_options,
        "manifest_missing": manifest_missing,
        "strategies": strategies,
    }


def populate_remediation_recommendations(results, default_project_path):
    """Calculates and attaches remediation info with multi-level strategies (Patch, Minor, Major, Parent Upgrade, Override) to each result."""
    manifest_file_cache = {}

    def _get_manifest_lines(m_path):
        if m_path not in manifest_file_cache:
            try:
                with open(m_path, "r", encoding="utf-8", errors="ignore") as f:
                    manifest_file_cache[m_path] = f.readlines()
            except Exception:
                manifest_file_cache[m_path] = []
        return manifest_file_cache[m_path]

    line_search_cache = {}

    def _find_line_idx(m_path, lines, pkg_name, tech, declared, is_engine):
        cache_key = (m_path, tech, pkg_name, str(declared), is_engine)
        if cache_key in line_search_cache:
            return line_search_cache[cache_key]

        found_line_idx = None
        best_score = -1
        for idx, line in enumerate(lines):
            matched = (f'"{pkg_name}"' in line or '"engines"' in line) if is_engine else match_line_for_dependency(line, pkg_name, tech)
            if matched:
                score = 1
                if declared:
                    ver_digits = re.search(r"\d+\.\d+", str(declared))
                    if ver_digits and ver_digits.group(0) in line or str(declared).strip() in line:
                        score = 2
                if score > best_score:
                    best_score = score
                    found_line_idx = idx + 1
                    if score == 2:
                        break
        line_search_cache[cache_key] = found_line_idx
        return found_line_idx

    manifest_files_cache = {}

    def _get_manifest_files(p_path, tech, is_engine):
        cache_key = (p_path, tech, is_engine)
        if cache_key not in manifest_files_cache:
            if is_engine:
                pkg_json = os.path.join(p_path, "package.json")
                manifest_files_cache[cache_key] = [pkg_json] if os.path.exists(pkg_json) else []
            else:
                manifest_files_cache[cache_key] = find_manifest_files(p_path, tech)
        return manifest_files_cache[cache_key]

    total_items = len(results)
    last_reported_pct = -1

    for idx, r in enumerate(results, 1):
        if total_items > 0:
            pct = int((idx / total_items) * 100)
            if pct != last_reported_pct or idx == total_items or idx % 25 == 0:
                sys.stdout.write(
                    f"\r{COLOR_GRAY}{ICON_INFO} Processing results: {pct}% ({idx}/{total_items} packages)...{COLOR_RESET}"
                )
                sys.stdout.flush()
                last_reported_pct = pct

        r["remediation"] = None

        is_outdated = r.get("status") in {"major", "minor", "patch", "minor-major", "patch-major"}
        has_vulns = bool(r.get("vulnerabilities"))
        is_depr = bool(r.get("deprecated"))

        if not (is_outdated or has_vulns or is_depr):
            continue

        project_path = r.get("project_path") or default_project_path
        tech = r.get("technology")
        if not tech:
            continue

        name = r.get("name")
        declared = r.get("declared")
        installed = r.get("installed")
        dep_type = r.get("dep_type")

        clean_installed = installed[0] if (isinstance(installed, list) and installed) else installed
        latest_patch = r.get("latest_patch")
        latest_sm = r.get("latest_same_major")
        latest_abs = r.get("latest_absolute") or r.get("latest")

        clean_inst_v = _clean_version_str(clean_installed)
        clean_decl_v = _clean_version_str(declared)

        if latest_patch and _clean_version_str(latest_patch) in (clean_inst_v, clean_decl_v):
            latest_patch = None
        if latest_sm and (
            _clean_version_str(latest_sm) in (clean_inst_v, clean_decl_v)
            or _clean_version_str(latest_sm) == _clean_version_str(latest_patch)
        ):
            latest_sm = None
        if latest_abs and " or " not in str(latest_abs) and (
            _clean_version_str(latest_abs) in (clean_inst_v, clean_decl_v)
            or _clean_version_str(latest_abs) == _clean_version_str(latest_sm)
            or _clean_version_str(latest_abs) == _clean_version_str(latest_patch)
        ):
            latest_abs = None

        manifest_files = _get_manifest_files(project_path, tech, r.get("is_engine", False))
        if not manifest_files:
            continue

        manifest_path = manifest_files[0]
        lines = _get_manifest_lines(manifest_path)
        if not lines:
            continue

        found_line_idx = _find_line_idx(manifest_path, lines, name, tech, declared, r.get("is_engine", False))
        manifest_missing = (found_line_idx is None and dep_type != "Transitive" and not r.get("required_by"))

        strategies = []

        if dep_type != "Transitive" or found_line_idx is not None:
            strategies.extend(_populate_direct_strategies(
                r, manifest_path, found_line_idx, name, declared, tech, latest_patch, latest_sm, latest_abs
            ))

        if dep_type == "Transitive" and found_line_idx is None:
            strategies.extend(_populate_parent_strategies(r, results, manifest_path, lines, tech, name, _find_line_idx))
            strategies.extend(_populate_override_strategies(
                manifest_path, name, tech, latest_patch, latest_sm, latest_abs, clean_installed, bool(strategies)
            ))

        remed_dict = _build_final_remediation(strategies, manifest_missing)
        if remed_dict:
            r["remediation"] = remed_dict
            if manifest_missing:
                r["manifest_missing"] = True

    if total_items > 0:
        sys.stdout.write(
            f"\r{COLOR_GRAY}{ICON_INFO} Processing results: 100% ({total_items}/{total_items} packages)... Done.{COLOR_RESET}\n"
        )
        sys.stdout.flush()


# Compressed embedded HTML Report Template (gzip + base64)
# To edit the template with full IDE support, modify 'assets/report_template.html'
# and run 'python scripts/pack_template.py' to update this string.
_HTML_TEMPLATE_GZIP_B64 = (
    "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"
    "AA=="
)


class HTMLReportTemplateProvider:
    """Provides the HTML/CSS/JS template for interactive dependency reports."""

    _cached_template = None

    @classmethod
    def get_template(cls):
        if cls._cached_template is not None:
            return cls._cached_template

        # 1. In local development mode, read from assets/report_template.html if present
        dev_template_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "assets",
            "report_template.html",
        )
        if os.path.exists(dev_template_path):
            try:
                with open(dev_template_path, "r", encoding="utf-8") as f:
                    cls._cached_template = f.read()
                    return cls._cached_template
            except OSError:
                pass

        # 2. Standalone / CI/CD fallback: decompress from embedded binary constant
        cls._cached_template = gzip.decompress(
            base64.b64decode(_HTML_TEMPLATE_GZIP_B64)
        ).decode("utf-8")
        return cls._cached_template


def export_html_report(results, pkg_data, filepath, vuls_enabled=False):
    """Exports results as a rich, interactive HTML dashboard report."""

    def escape_js_string(s):
        if not s:
            return ""
        s = str(s)
        s = s.replace("\\", "\\\\")
        s = s.replace("'", "\\'")
        s = s.replace('"', '\\"')
        s = s.replace("\n", "\\n")
        s = s.replace("\r", "\\r")
        return s

    def js_arg(val):
        return escape_html(escape_js_string(val))

    # normalize_severity_to_text was moved to the global scope as get_severity_level

    try:
        # Calculate summary statistics
        total = len(results)
        # Optimization: Use sets for O(1) membership lookups
        up_to_date = sum(1 for r in results if r["status"] in {"up-to-date", "local"})
        outdated = sum(
            1
            for r in results
            if r["status"] in {"major", "minor", "patch", "minor-major", "patch-major"}
        )
        deprecated = sum(1 for r in results if r["deprecated"])
        errors = sum(1 for r in results if r["status"] == "error")

        total_vulns = 0
        suppressed_vulns = 0

        if vuls_enabled:
            total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
            suppressed_vulns = sum(
                len(r.get("suppressed_vulnerabilities", [])) for r in results
            )

        # Count severities for SVG Chart
        malicious = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        unknown = 0

        for r in results:
            for v in r.get("vulnerabilities", []):
                level = get_severity_level(v)
                if level == "malicious":
                    malicious += 1
                elif level == "critical":
                    critical += 1
                elif level == "high":
                    high += 1
                elif level == "medium":
                    medium += 1
                elif level == "low":
                    low += 1
                else:
                    unknown += 1

        max_count = max(malicious, critical, high, medium, low, unknown, 1)
        max_h = 130

        mal_h = int((malicious / max_count) * max_h)
        crit_h = int((critical / max_count) * max_h)
        high_h = int((high / max_count) * max_h)
        med_h = int((medium / max_count) * max_h)
        low_h = int((low / max_count) * max_h)
        unkn_h = int((unknown / max_count) * max_h)

        base_y = 180
        mal_y = base_y - mal_h
        crit_y = base_y - crit_h
        high_y = base_y - high_h
        med_y = base_y - med_h
        low_y = base_y - low_h
        unkn_y = base_y - unkn_h

        mal_val_y = mal_y - 8 if malicious > 0 else base_y - 8
        crit_val_y = crit_y - 8 if critical > 0 else base_y - 8
        high_val_y = high_y - 8 if high > 0 else base_y - 8
        med_val_y = med_y - 8 if medium > 0 else base_y - 8
        low_val_y = low_y - 8 if low > 0 else base_y - 8
        unkn_val_y = unkn_y - 8 if unknown > 0 else base_y - 8

        # Build SVG Chart
        svg_chart = f"""
        <svg viewBox="0 0 500 220" width="100%" height="220" style="background: #111827; border-radius: 12px; border: 1px solid #374151; padding: 15px; box-sizing: border-box;">
            <!-- Grid lines -->
            <line x1="30" y1="50" x2="470" y2="50" stroke="#374151" stroke-dasharray="3" />
            <line x1="30" y1="115" x2="470" y2="115" stroke="#374151" stroke-dasharray="3" />
            <line x1="30" y1="180" x2="470" y2="180" stroke="#4b5563" />
            
            <!-- MALICIOUS -->
            <rect x="45" y="{mal_y}" width="40" height="{mal_h}" fill="url(#grad-mal)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{mal_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{mal_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="65" y="{mal_val_y}" fill="#ef4444" font-size="10" text-anchor="middle" font-weight="bold" font-family="sans-serif">☠️ {malicious}</text>
            <text x="65" y="198" fill="#fca5a5" font-size="9" text-anchor="middle" font-family="sans-serif" font-weight="bold">MALICIOUS</text>
            
            <!-- CRITICAL -->
            <rect x="115" y="{crit_y}" width="40" height="{crit_h}" fill="url(#grad-crit)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{crit_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{crit_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="135" y="{crit_val_y}" fill="#ef4444" font-size="10" text-anchor="middle" font-weight="bold" font-family="sans-serif">{critical}</text>
            <text x="135" y="198" fill="#9ca3af" font-size="9" text-anchor="middle" font-family="sans-serif">CRITICAL</text>
            
            <!-- HIGH -->
            <rect x="185" y="{high_y}" width="40" height="{high_h}" fill="url(#grad-high)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{high_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{high_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="205" y="{high_val_y}" fill="#f97316" font-size="10" text-anchor="middle" font-weight="bold" font-family="sans-serif">{high}</text>
            <text x="205" y="198" fill="#9ca3af" font-size="9" text-anchor="middle" font-family="sans-serif">HIGH</text>
            
            <!-- MEDIUM -->
            <rect x="255" y="{med_y}" width="40" height="{med_h}" fill="url(#grad-med)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{med_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{med_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="275" y="{med_val_y}" fill="#eab308" font-size="10" text-anchor="middle" font-weight="bold" font-family="sans-serif">{medium}</text>
            <text x="275" y="198" fill="#9ca3af" font-size="9" text-anchor="middle" font-family="sans-serif">MEDIUM</text>
            
            <!-- LOW -->
            <rect x="325" y="{low_y}" width="40" height="{low_h}" fill="url(#grad-low)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{low_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{low_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="345" y="{low_val_y}" fill="#0ea5e9" font-size="10" text-anchor="middle" font-weight="bold" font-family="sans-serif">{low}</text>
            <text x="345" y="198" fill="#9ca3af" font-size="9" text-anchor="middle" font-family="sans-serif">LOW</text>
            
            <!-- UNKNOWN -->
            <rect x="395" y="{unkn_y}" width="40" height="{unkn_h}" fill="url(#grad-unkn)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{unkn_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{unkn_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="415" y="{unkn_val_y}" fill="#9ca3af" font-size="10" text-anchor="middle" font-weight="bold" font-family="sans-serif">{unknown}</text>
            <text x="415" y="198" fill="#9ca3af" font-size="9" text-anchor="middle" font-family="sans-serif">UNKNOWN</text>
            
            <!-- Gradients Definitions -->
            <defs>
                <linearGradient id="grad-mal" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#fca5a5" />
                    <stop offset="100%" stop-color="#7f1d1d" />
                </linearGradient>
                <linearGradient id="grad-crit" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#f87171" />
                    <stop offset="100%" stop-color="#991b1b" />
                </linearGradient>
                <linearGradient id="grad-high" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#fb923c" />
                    <stop offset="100%" stop-color="#9a3412" />
                </linearGradient>
                <linearGradient id="grad-med" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#fde047" />
                    <stop offset="100%" stop-color="#854d0e" />
                </linearGradient>
                <linearGradient id="grad-low" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#38bdf8" />
                    <stop offset="100%" stop-color="#075985" />
                </linearGradient>
                <linearGradient id="grad-unkn" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stop-color="#9ca3af" />
                    <stop offset="100%" stop-color="#4b5563" />
                </linearGradient>
            </defs>
        </svg>
        """

        pkg_counts = {}
        for r in results:
            pkg_counts[r["name"]] = pkg_counts.get(r["name"], 0) + 1

        # Check if we should show the project path in the global header or per-card
        unique_project_paths = sorted(
            {r.get("project_path") for r in results if r.get("project_path")}
        )
        show_project_globally = len(unique_project_paths) <= 1

        unique_technologies = sorted(
            {r.get("technology") for r in results if r.get("technology")}
        )

        technology_dropdown_html = ""
        if len(unique_technologies) > 1:
            tech_rows = []
            for tech in unique_technologies:
                tech_esc = escape_html(tech)
                tech_val_esc = escape_html(tech.lower())
                tech_rows.append(f"""
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="{tech_val_esc}" checked onchange="filterPackages()"> {tech_esc}</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, '{tech_val_esc}')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>""")
            technology_dropdown_html = f"""
                <div class="filter-group">
                    <button class="filter-btn btn-facet" data-cat="technology" onclick="setCategory('technology', event)">
                        Technology <span class="chevron-inline">▼</span>
                    </button>
                    <div class="filter-dropdown" id="dropdown-technology">
                        {''.join(tech_rows)}
                    </div>
                </div>"""

        project_path_header_html = ""
        if show_project_globally and unique_project_paths:
            single_path = unique_project_paths[0]
            techs = sorted(
                {
                        r.get("technology")
                        for r in results
                        if r.get("project_path") == single_path and r.get("technology")
                    }
            )
            tech_suffix = f" [{', '.join(techs)}]" if techs else ""
            project_path_header_html = f"<div>Path: <strong>{escape_html(single_path)}{escape_html(tech_suffix)}</strong></div>"
        elif not show_project_globally:
            project_path_header_html = f"<div>Projects: <strong>Multiple ({len(unique_project_paths)})</strong></div>"

        # Extract unique vulnerabilities to global store and build compact JSON packages
        vulnerability_store = {}
        for r in results:
            for v in r.get("vulnerabilities", []):
                vid = v["id"]
                if vid not in vulnerability_store:
                    vulnerability_store[vid] = {
                        "severity": get_severity_level(v),
                        "summary": v.get("summary", ""),
                        "details": v.get("details", ""),
                    }
            for sv in r.get("suppressed_vulnerabilities", []):
                vid = sv["id"]
                if vid not in vulnerability_store:
                    vulnerability_store[vid] = {
                        "severity": get_severity_level(sv),
                        "summary": sv.get("summary", ""),
                        "details": sv.get("details", ""),
                    }

        json_packages = []
        for r in results:
            name = r["name"]
            declared = r["declared"]
            installed = r["installed"]

            is_direct_install = False
            if declared:
                if pkg_counts.get(name, 0) == 1:
                    is_direct_install = True
                else:
                    is_direct_install = check_semver_satisfies(installed, declared)

            dep_type = r.get("dep_type")
            if not dep_type:
                dep_type = "Transitive"
                if r.get("is_engine", False):
                    dep_type = "Engine"
                elif pkg_data and is_direct_install:
                    if name in pkg_data.get("all_direct", {}):
                        dep_type = "Direct"
                    elif name in pkg_data.get("devDependencies", {}):
                        dep_type = "Dev"

            if (
                r.get("required_by")
                and not r.get("is_engine", False)
                and ("indirect" in r.get("required_by", []) or dep_type == "Transitive")
            ):
                dep_type = "Transitive"

            pkg_record = {
                "name": name,
                "declared": declared,
                "installed": installed,
                "latest": r.get("latest"),
                "latest_same_major": r.get("latest_same_major"),
                "latest_absolute": r.get("latest_absolute"),
                "status": r["status"],
                "deprecated": r["deprecated"],
                "error": r["error"],
                "missing_checksum": r.get("missing_checksum", False),
                "weak_checksum": r.get("weak_checksum", False),
                "mismatch_checksum": r.get("mismatch_checksum", False),
                "vulnerabilities": [v["id"] for v in r.get("vulnerabilities", [])],
                "suppressed_vulnerabilities": [
                    {
                        "id": sv["id"],
                        "suppressed_reason": sv.get(
                            "suppressed_reason", "No reason provided"
                        ),
                        "justification": sv.get("justification", "N/A"),
                        "expires_at": sv.get("expires_at", "N/A"),
                        "approved_by": sv.get("approved_by", ""),
                    }
                    for sv in r.get("suppressed_vulnerabilities", [])
                ],
                "required_by": r.get("required_by", []),
                "is_engine": r.get("is_engine", False),
                "technology": r.get("technology", ""),
                "project_path": r.get("project_path", ""),
                "dep_type": dep_type,
                "remediation": r.get("remediation"),
                "excluded_warning": r.get("excluded_warning"),
                "compare_url": r.get("compare_url"),
                "releases_url": r.get("releases_url"),
            }
            # Remove keys with None, False, empty list, or empty string to optimize JSON payload size
            pkg_record = {
                k: v
                for k, v in pkg_record.items()
                if v is not None and v is not False and v != "" and v != []
            }
            json_packages.append(pkg_record)

        # Sort results for JSON display: packages with higher severity vulnerabilities first
        if vuls_enabled:
            severity_order = {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
                "unknown": 0,
            }

            def get_pkg_max_severity(pkg):
                vuln_ids = pkg.get("vulnerabilities", [])
                sevs = [
                    vulnerability_store[vid]["severity"]
                    for vid in vuln_ids
                    if vid in vulnerability_store
                ]
                if not sevs:
                    return 1
                return -max(severity_order.get(s.lower(), 0) for s in sevs)

            json_packages.sort(
                key=lambda p: (get_pkg_max_severity(p), p["name"].lower())
            )
        else:
            json_packages.sort(key=lambda p: p["name"].lower())

        # FIXED: XSS Mitigation via JSON serialization
        escaped_packages_json = (
            json.dumps(json_packages)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )
        escaped_vulns_json = (
            json.dumps(vulnerability_store)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )

        # HTML Master Template rendering
        template_str = HTMLReportTemplateProvider.get_template()
        template = string.Template(template_str)

        project_title = escape_html(
            results[0]["name"].split(":")[0]
            if (results and ":" in results[0]["name"])
            else "Project"
        )
        svg_chart_html = (
            svg_chart
            if vuls_enabled
            else '<div style="background:#111827; border-radius:12px; border:1px solid #374151; height:220px; display:flex; align-items:center; justify-content:center; color:#9ca3af; font-size:14px;">Vulnerabilities scan disabled. Run with --vuls to enable charts.</div>'
        )

        mapping = {
            "VERSION": VERSION,
            "deprecated": str(deprecated),
            "errors": str(errors),
            "malicious": str(malicious),
            "outdated": str(outdated),
            "project_path_header_html": project_path_header_html,
            "suppressed_vulns": str(suppressed_vulns),
            "total": str(total),
            "total_vulns": str(total_vulns),
            "up_to_date": str(up_to_date),
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "project_title": project_title,
            "svg_chart": svg_chart_html,
            "packages_json_data": escaped_packages_json,
            "vulns_json_data": escaped_vulns_json,
            "show_project_globally": json.dumps(show_project_globally),
            "unique_project_paths": json.dumps(unique_project_paths)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026"),
            "unique_technologies": json.dumps(unique_technologies)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026"),
            "technology_dropdown_html": technology_dropdown_html,
            "vuls_enabled": json.dumps(vuls_enabled),
        }

        html_content = template.safe_substitute(mapping)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(
            f"{COLOR_GREEN}{ICON_OK} HTML interactive dashboard successfully exported to {filepath}{COLOR_RESET}"
        )
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to export HTML report: {e}{COLOR_RESET}")


# ==============================================================================
# CLI Entrypoint
# ==============================================================================

# Populate runner functions in global TECHNOLOGIES dictionary now that functions are defined
TECHNOLOGIES["npm"]["runner"] = run_npm_checker
TECHNOLOGIES["pip"]["runner"] = run_pip_checker
TECHNOLOGIES["nuget"]["runner"] = run_nuget_checker
TECHNOLOGIES["php"]["runner"] = run_composer_checker
TECHNOLOGIES["maven"]["runner"] = run_maven_checker
TECHNOLOGIES["go"]["runner"] = run_go_checker
TECHNOLOGIES["rust"]["runner"] = run_rust_checker
TECHNOLOGIES["ruby"]["runner"] = run_ruby_checker
TECHNOLOGIES["gradle"]["runner"] = run_gradle_checker
TECHNOLOGIES["android"]["runner"] = run_gradle_checker


def detect_technologies(dir_path):
    """Detects which technologies are present in a given directory."""
    detected = []
    if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
        return detected
    try:
        files = os.listdir(dir_path)
    except Exception:
        return detected

    lower_files = [f.lower() for f in files]

    for tech, info in TECHNOLOGIES.items():
        matched = False
        for pattern in info["files"]:
            if pattern.startswith("."):
                if any(f.endswith(pattern.lower()) for f in lower_files):
                    matched = True
                    break
            else:
                if pattern.lower() in lower_files:
                    matched = True
                    break
        if matched:
            detected.append(tech)

    if "gradle" in detected and "android" in detected:
        detected.remove("android")

    return detected


def find_projects_recursively(base_path):
    """Walks the directory recursively to find all projects and their detected technologies."""
    projects = []
    ignored_dirs = {
        ".git",
        ".github",
        ".svn",
        ".hg",
        "node_modules",
        "bower_components",
        "venv",
        ".venv",
        "env",
        ".env",
        "bin",
        "obj",
        "target",
        "vendor",
        ".gradle",
        "__pycache__",
        ".idea",
        ".vscode",
        ".agents",
    }

    detected_base = detect_technologies(base_path)
    if detected_base:
        projects.append((base_path, detected_base))

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d.lower() not in ignored_dirs]
        for d in dirs:
            dir_path = os.path.join(root, d)
            detected = detect_technologies(dir_path)
            if detected:
                projects.append((dir_path, detected))

    return projects


# Old get_severity_level and CVSS calculation functions were removed to unify the severity logic


def check_pipeline_failure(results, fail_config):
    """Checks if the vulnerability thresholds are breached to fail the build.
    fail_config can be 'any' or a string like 'critical:2,high:4'.
    """
    if not fail_config:
        return False

    total_vulns = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}

    for r in results:
        for vuln in r.get("vulnerabilities", []):
            total_vulns += 1
            severity = get_severity_level(vuln)
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["unknown"] += 1

    if fail_config == "any":
        return total_vulns > 0

    try:
        thresholds = {}
        for part in fail_config.split(","):
            if ":" in part:
                sev, val = part.split(":", 1)
                sev_clean = sev.strip().lower()
                if sev_clean == "moderate":
                    sev_clean = "medium"
                thresholds[sev_clean] = int(val.strip())

        for sev, limit in thresholds.items():
            if sev in severity_counts and severity_counts[sev] >= limit:
                print(
                    f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {severity_counts[sev]} {sev.upper()} vulnerabilities (Limit: {limit}){COLOR_RESET}"
                )
                return True
            elif sev == "unknown" and severity_counts["unknown"] >= limit:
                print(
                    f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {severity_counts['unknown']} UNKNOWN vulnerabilities (Limit: {limit}){COLOR_RESET}"
                )
                return True
    except Exception as e:
        print(
            f"\n{COLOR_YELLOW}{ICON_WARN} Warning: Failed to parse --fail-on-vulns config '{fail_config}': {e}. Falling back to fail on any vulnerability.{COLOR_RESET}"
        )
        return total_vulns > 0

    return False


def check_pipeline_failure_deprecated(results, fail_config):
    """Checks if the deprecated threshold is breached to fail the build.
    fail_config can be 'any' or a string representing a minimum count (e.g. '3').
    """
    if not fail_config:
        return False

    deprecated_count = sum(1 for r in results if r.get("deprecated"))

    limit = 1
    if fail_config != "any":
        try:
            limit = int(fail_config.strip())
        except ValueError:
            print(
                f"\n{COLOR_YELLOW}{ICON_WARN} Warning: Failed to parse --fail-on-deprecated config '{fail_config}'. Falling back to fail on any deprecated package.{COLOR_RESET}"
            )
            limit = 1

    if deprecated_count >= limit:
        print(
            f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {deprecated_count} deprecated dependency/dependencies (Limit: {limit}){COLOR_RESET}"
        )
        return True
    return False


def check_pipeline_failure_outdated(results, fail_config):
    """Checks if the outdated threshold is breached to fail the build.
    fail_config can be 'any', a number (e.g. '3'), or specific thresholds (e.g. 'major:2,minor:4').
    """
    if not fail_config:
        return False

    major_count = sum(
        # Optimization: Use sets for O(1) membership lookups
        1
        for r in results
        if r.get("status") in {"major", "minor-major", "patch-major"}
    )
    # Optimization: Use sets for O(1) membership lookups
    minor_count = sum(1 for r in results if r.get("status") in {"minor", "minor-major"})
    # Optimization: Use sets for O(1) membership lookups
    patch_count = sum(1 for r in results if r.get("status") in {"patch", "patch-major"})
    total_outdated = sum(
        1
        for r in results
        # Optimization: Use sets for O(1) membership lookups
        if r.get("status") in {"patch", "minor", "major", "minor-major", "patch-major"}
    )

    if fail_config == "any":
        if total_outdated > 0:
            print(
                f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {total_outdated} outdated dependency/dependencies (Limit: 1){COLOR_RESET}"
            )
            return True
        return False

    try:
        limit = int(fail_config.strip())
        if total_outdated >= limit:
            print(
                f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {total_outdated} outdated dependency/dependencies (Limit: {limit}){COLOR_RESET}"
            )
            return True
        return False
    except ValueError:
        pass

    try:
        thresholds = {}
        for part in fail_config.split(","):
            if ":" in part:
                status_type, val = part.split(":", 1)
                status_clean = status_type.strip().lower()
                thresholds[status_clean] = int(val.strip())

        status_counts = {
            "major": major_count,
            "minor": minor_count,
            "patch": patch_count,
        }

        for status_type, limit in thresholds.items():
            if status_type in status_counts and status_counts[status_type] >= limit:
                print(
                    f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {status_counts[status_type]} {status_type.upper()} outdated packages (Limit: {limit}){COLOR_RESET}"
                )
                return True
    except Exception as e:
        print(
            f"\n{COLOR_YELLOW}{ICON_WARN} Warning: Failed to parse --fail-on-outdated config '{fail_config}': {e}. Falling back to fail on any outdated package.{COLOR_RESET}"
        )
        if total_outdated > 0:
            print(
                f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {total_outdated} outdated dependency/dependencies (Limit: 1){COLOR_RESET}"
            )
            return True

    return False


def check_for_updates():
    """Checks for updates from remote version.md and writes local version.md."""
    url = "https://raw.githubusercontent.com/brunoevn/kevlar-checkdeps/main/version.md"
    print(f"{COLOR_GRAY}{ICON_INFO} Checking for updates from GitHub...{COLOR_RESET}")

    latest_version = "Unknown"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Kevlar-CheckDeps-Updater"}
        )
        with safe_urlopen(req, timeout=5) as response:
            content = response.read(1024).decode("utf-8")

        match = re.search(r'VERSION\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            latest_version = match.group(1)
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Error checking for updates: {e}{COLOR_RESET}")
        latest_version = "Error"

    status = "Up-to-date"
    if latest_version not in {"Unknown", "Error"}:
        try:
            curr_parts = [int(x) for x in VERSION.split(".")]
            late_parts = [int(x) for x in latest_version.split(".")]
            if late_parts > curr_parts:
                status = "Update Available"
        except Exception:
            if latest_version != VERSION:
                status = "Update Available"

    if status == "Update Available":
        print(
            f"{COLOR_YELLOW}{ICON_WARN} A new version v{latest_version} is available! (Current: v{VERSION}).{COLOR_RESET}"
        )
    elif latest_version not in {"Unknown", "Error"}:
        print(f"{COLOR_GREEN}{ICON_OK} Kevlar is up-to-date (v{VERSION}).{COLOR_RESET}")


def print_banner():
    banner = f"""{COLOR_BOLD}{COLOR_CYAN}
 _  __ _____ __     __ _        _    ____  
| |/ /| ____|\\ \\   / /| |      / \\  |  _ \\ 
| ' / |  _|   \\ \\ / / | |     / _ \\ | |_) |
| . \\ | |___   \\ V /  | |___ / ___ \\|  _ < 
|_|\\_\\|_____|   \\_/   |_____/_/   \\_\\_| \\_\\  v{VERSION}  {COLOR_GRAY}By Bruno Nielsen{COLOR_RESET}
  {COLOR_CYAN}https://github.com/brunoevn/kevlar-checkdeps{COLOR_RESET}
"""
    print(banner)


def setup_argparse():
    parser = argparse.ArgumentParser(
        description="Kevlar CheckDeps: Generic Dependency Checker & SCA Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
Examples:
  python kevlar.py --tech npm --path ./Backend
  python kevlar.py --tech npm --path ./Frontend --all --show-all
  python kevlar.py --tech npm --output report.json
        """,
    )

    parser.add_argument(
        "--help",
        "-h",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit.",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"kevlar CheckDeps v{VERSION}",
        help="Show program's version number and exit.",
    )
    parser.add_argument(
        "--update", action="store_true", help="Check for updates from GitHub."
    )
    parser.add_argument(
        "--tech",
        "-t",
        required=False,
        choices=[
            "npm",
            "pip",
            "nuget",
            "php",
            "maven",
            "go",
            "rust",
            "ruby",
            "gradle",
            "android",
            "auto",
        ],
        help="The package manager / technology to check (or 'auto' to detect automatically).",
    )
    parser.add_argument(
        "--path",
        "-p",
        default=".",
        help="The directory path containing the package files (default: current directory).",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Scan all dependencies (including transitive ones), rather than just direct ones.",
    )
    parser.add_argument(
        "--concurrent",
        "-c",
        type=int,
        default=10,
        help="Number of concurrent network requests (default: 10).",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to export the report file (supports .json, .md, and .html formats).",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all dependencies in the output, even if they are up-to-date.",
    )
    parser.add_argument(
        "--vuls",
        "-v",
        action="store_true",
        help="Check security vulnerabilities using the Google OSV database.",
    )
    parser.add_argument(
        "--fail-on-vulns",
        nargs="?",
        const="any",
        default=None,
        help="Exit with code 1 if security vulnerabilities are found. Optionally specify thresholds, e.g., 'critical:2,high:4'.",
    )
    parser.add_argument(
        "--fail-on-deprecated",
        nargs="?",
        const="any",
        default=None,
        help="Exit with code 1 if deprecated dependencies are found. Optionally specify count threshold (e.g. '3').",
    )
    parser.add_argument(
        "--fail-on-outdated",
        nargs="?",
        const="any",
        default=None,
        help="Exit with code 1 if outdated dependencies are found. Optionally specify count threshold (e.g., '3') or specific types (e.g., 'major:2,minor:4').",
    )
    parser.add_argument(
        "--suppress",
        "-s",
        default=None,
        help="Path to a JSON file containing vulnerability suppressions (default: look for 'kevlar-suppressions.json').",
    )
    parser.add_argument(
        "--scan-all",
        action="store_true",
        help="Recursively scan the path for multiple projects, automatically detecting their technologies.",
    )
    parser.add_argument(
        "--format",
        choices=["html", "json", "sarif", "both"],
        help="Output report format when using --scan-all. 'both' generates HTML and JSON.",
    )
    parser.add_argument(
        "--no-show-console",
        "-n",
        action="store_true",
        help="Suppress printing detailed dependency tables and vulnerability lists in the console, displaying only progress logs, project headers, and summary reports.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detailed stack trace and internal error messages to stdout during execution.",
    )

    return parser


def run_scan_all(args, parser):
    print(
        f"{COLOR_GRAY}{ICON_INFO} Scanning recursively for projects in: {args.path}{COLOR_RESET}"
    )
    projects = find_projects_recursively(args.path)
    if not projects:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No projects detected in path: {args.path}{COLOR_RESET}"
        )
        sys.exit(0)

    if args.tech:
        filtered_projects = []
        for project_path, techs in projects:
            if args.tech in techs:
                filtered_projects.append((project_path, [args.tech]))
        projects = filtered_projects
        if not projects:
            print(
                f"{COLOR_YELLOW}{ICON_WARN} No projects matching technology '{args.tech}' found in path: {args.path}{COLOR_RESET}"
            )
            sys.exit(0)

    print(
        f"{COLOR_GRAY}{ICON_INFO} Found {len(projects)} project(s) to scan.{COLOR_RESET}"
    )

    combined_results = []
    combined_dependencies = {}
    combined_devDependencies = {}
    combined_all_direct = {}
    total_elapsed = 0.0
    sarif_runs = []

    original_path = args.path
    original_tech = getattr(args, "tech", None)

    generated_report_basenames = set()

    for project_path, techs in projects:
        for tech in techs:
            tech_info = TECHNOLOGIES.get(tech)
            if not tech_info:
                continue

            print()
            print("=" * 80)
            print(f"Project: {project_path} [{tech}]")
            print("=" * 80)

            try:
                args.path = project_path
                args.tech = tech
                results, pkg_data, elapsed = tech_info["runner"](args)

                if not results:
                    continue

                for r in results:
                    r["project_path"] = project_path
                    r["technology"] = tech

                populate_remediation_recommendations(results, project_path)
                validate_configuration_drift(results)
                apply_vulnerability_suppressions(
                    results, args.suppress, project_path=project_path
                )
                results = sorted(results, key=lambda x: x["name"].lower())

                print_results_table(
                    results,
                    pkg_data,
                    args.show_all,
                    args.vuls,
                    getattr(args, "no_show_console", False),
                )
                print_summary(results, elapsed, args.vuls)

                rel_path = os.path.relpath(project_path, original_path)
                if rel_path == ".":
                    proj_dirname = os.path.basename(os.path.abspath(project_path))
                    if not proj_dirname:
                        proj_dirname = "project"
                else:
                    proj_dirname = rel_path

                proj_dirname = proj_dirname.replace("/", "_").replace("\\", "_")
                safe_proj_dirname = re.sub(r"[^\w\-]", "_", proj_dirname)
                safe_proj_dirname = re.sub(r"_{2,}", "_", safe_proj_dirname).strip("_")

                base_safe_name = safe_proj_dirname
                if base_safe_name in generated_report_basenames:
                    candidate = f"{base_safe_name}-{tech}"
                    if candidate in generated_report_basenames:
                        counter = 2
                        while f"{candidate}-{counter}" in generated_report_basenames:
                            counter += 1
                        safe_proj_dirname = f"{candidate}-{counter}"
                    else:
                        safe_proj_dirname = candidate

                generated_report_basenames.add(safe_proj_dirname)

                if args.format in {"html", "both"}:
                    proj_html_filepath = f"report-{safe_proj_dirname}.html"
                    export_html_report(results, pkg_data, proj_html_filepath, args.vuls)

                if args.format in {"json", "both"}:
                    proj_json_filepath = f"report-{safe_proj_dirname}.json"
                    export_json_report(results, proj_json_filepath)

                if args.format == "sarif":
                    run_obj = generate_sarif_run(results)
                    sarif_runs.append(run_obj)

                combined_results.extend(results)
                total_elapsed += elapsed

                if pkg_data:
                    combined_dependencies.update(pkg_data.get("dependencies", {}))
                    combined_devDependencies.update(pkg_data.get("devDependencies", {}))
                    combined_all_direct.update(pkg_data.get("all_direct", {}))
            except Exception as e:
                print(
                    f"{COLOR_RED}{ICON_ERROR} Error scanning project {project_path} with {tech}: {e}{COLOR_RESET}"
                )
            finally:
                args.path = original_path
                args.tech = original_tech

    if not combined_results:
        print(
            f"{COLOR_YELLOW}{ICON_WARN} No dependency check results collected from projects.{COLOR_RESET}"
        )
        sys.exit(0)


    combined_results = sorted(combined_results, key=lambda x: x["name"].lower())

    print()
    print("=" * 80)
    print("CONSOLIDATED SUMMARY")
    print("=" * 80)
    print_summary(
        combined_results, total_elapsed, args.vuls, projects_count=len(projects)
    )

    if args.format == "sarif" and sarif_runs:
        consolidated_path = "report-consolidated.sarif"
        try:
            consolidated_log = {
                "$schema": "https://schemastore.org/json/schema/sarif-2.1.0-rtm.5.json",
                "version": "2.1.0",
                "runs": sarif_runs,
            }
            with open(consolidated_path, "w", encoding="utf-8") as f:
                json.dump(consolidated_log, f, indent=2)
            print(
                f"\n{COLOR_GREEN}{ICON_OK} Consolidated SARIF report successfully exported to {consolidated_path}{COLOR_RESET}"
            )
        except Exception as e:
            print(
                f"\n{COLOR_RED}{ICON_ERROR} Failed to export consolidated SARIF report: {e}{COLOR_RESET}"
            )

    process_pipeline_failures(combined_results, args)
    sys.exit(0)


def run_auto_tech(args):
    detected_techs = detect_technologies(args.path)
    if not detected_techs:
        print(
            f"{COLOR_RED}{ICON_ERROR} No technology detected in path: {args.path}{COLOR_RESET}"
        )
        sys.exit(1)

    print(
        f"{COLOR_GRAY}{ICON_INFO} Automatically detected technology: {', '.join(detected_techs)}{COLOR_RESET}"
    )

    combined_results = []
    combined_dependencies = {}
    combined_devDependencies = {}
    combined_all_direct = {}
    total_elapsed = 0.0

    original_tech = args.tech
    try:
        for tech in detected_techs:
            tech_info = TECHNOLOGIES.get(tech)
            if not tech_info:
                continue

            if len(detected_techs) > 1:
                print()
                print("-" * 50)
                print(f"Running check for: {tech}")
                print("-" * 50)

            args.tech = tech
            results_tech, pkg_data_tech, elapsed_tech = tech_info["runner"](args)

            if not results_tech:
                continue

            for r in results_tech:
                r["project_path"] = args.path
                r["technology"] = tech

            combined_results.extend(results_tech)
            total_elapsed += elapsed_tech

            if pkg_data_tech:
                combined_dependencies.update(pkg_data_tech.get("dependencies", {}))
                combined_devDependencies.update(
                    pkg_data_tech.get("devDependencies", {})
                )
                combined_all_direct.update(pkg_data_tech.get("all_direct", {}))
    finally:
        args.tech = original_tech

    combined_pkg_data = {
        "dependencies": combined_dependencies,
        "devDependencies": combined_devDependencies,
        "all_direct": combined_all_direct,
    }

    return combined_results, combined_pkg_data, total_elapsed


def process_single_project_results(results, pkg_data, elapsed, args):
    if not results:
        sys.exit(0)

    for r in results:
        if "project_path" not in r:
            r["project_path"] = args.path
        if "technology" not in r:
            r["technology"] = args.tech if args.tech != "auto" else r.get("technology")

    populate_remediation_recommendations(results, args.path)
    validate_configuration_drift(results)
    apply_vulnerability_suppressions(results, args.suppress, project_path=args.path)
    results = sorted(results, key=lambda x: x["name"].lower())

    print_results_table(
        results,
        pkg_data,
        args.show_all,
        args.vuls,
        getattr(args, "no_show_console", False),
    )
    print_summary(results, elapsed, args.vuls)

    if args.output:
        if args.output.lower().endswith(".json"):
            export_json_report(results, args.output)
        elif args.output.lower().endswith(".md"):
            export_markdown_report(results, pkg_data, args.output, args.vuls)
        elif args.output.lower().endswith(".html"):
            export_html_report(results, pkg_data, args.output, args.vuls)
        elif args.output.lower().endswith(".sarif"):
            export_sarif_report(results, args.output)
        else:
            print(
                f"{COLOR_YELLOW}{ICON_WARN} Unknown output format. Export supports .json, .md, .html, or .sarif extension.{COLOR_RESET}"
            )

    process_pipeline_failures(results, args)


def process_pipeline_failures(results, args):
    failed = False
    if args.fail_on_vulns and check_pipeline_failure(results, args.fail_on_vulns):
        failed = True
    if args.fail_on_deprecated and check_pipeline_failure_deprecated(
        results, args.fail_on_deprecated
    ):
        failed = True
    if args.fail_on_outdated and check_pipeline_failure_outdated(
        results, args.fail_on_outdated
    ):
        failed = True

    if failed:
        sys.exit(1)


def main():
    init_colors_and_encoding()

    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"kevlar CheckDeps v{VERSION}")
        sys.exit(0)
    elif "--update" in sys.argv:
        check_for_updates()
        sys.exit(0)

    print_banner()

    parser = setup_argparse()
    args = parser.parse_args()

    global DEBUG_MODE
    DEBUG_MODE = args.debug

    if not args.scan_all and not args.tech:
        args.tech = "auto"

    if args.scan_all:
        if args.output:
            parser.error(
                "cannot specify --output with --scan-all. The report is automatically generated, format is controlled via --format"
            )
        if not args.format:
            parser.error(
                "the following argument is required when using --scan-all: --format"
            )
    else:
        if args.format:
            parser.error(
                "cannot specify --format without --scan-all. For single-project scan, specify output filename via --output"
            )

    if args.scan_all:
        run_scan_all(args, parser)
        return

    if args.tech == "auto":
        results, pkg_data, elapsed = run_auto_tech(args)
    else:
        tech_info = TECHNOLOGIES.get(args.tech)
        if not tech_info:
            print(
                f"{COLOR_RED}{ICON_ERROR} Unsupported technology: {args.tech}{COLOR_RESET}"
            )
            sys.exit(1)

        results, pkg_data, elapsed = tech_info["runner"](args)

    process_single_project_results(results, pkg_data, elapsed, args)


if __name__ == "__main__":
    main()
