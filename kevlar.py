#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dependency Checker Utility
Checks project dependencies for outdated, deprecated, or obsolete versions.
Supports security vulnerability scanning via Google OSV API.
Supports multiple technologies.
"""

import os
import sys
import string
import json
import re
import argparse
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, date
import xml.etree.ElementTree as ET
import codecs
import base64
import xml.parsers.expat
import traceback
import unicodedata
import ctypes

# Safe terminal output wrapping to prevent UnicodeEncodeError on Windows
class SafeWriter:
    def __init__(self, original_stream):
        self.original_stream = original_stream
        self.encoding = (original_stream.encoding if hasattr(original_stream, "encoding") else None) or "utf-8"
    def write(self, data):
        try:
            self.original_stream.write(data)
        except UnicodeEncodeError:
            self.original_stream.write(data.encode(self.encoding, errors="replace").decode(self.encoding))
    def flush(self):
        if hasattr(self.original_stream, "flush"):
            self.original_stream.flush()

sys.stdout = SafeWriter(sys.stdout)
sys.stderr = SafeWriter(sys.stderr)

VERSION = "1.9.3"

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
COLOR_RED = "\033[38;5;203m"       # Sleek soft red
COLOR_YELLOW = "\033[38;5;221m"    # Soft warm yellow
COLOR_GREEN = "\033[38;5;120m"     # Bright fresh green
COLOR_CYAN = "\033[38;5;86m"       # Pastel cyan
COLOR_MAGENTA = "\033[38;5;213m"   # Bright pinkish/magenta
COLOR_GRAY = "\033[38;5;244m"      # Medium gray

# Default Unicode Icons for visual cues
ICON_OK = "✔"
ICON_INFO = "ℹ"
ICON_WARN = "⚠"
ICON_ERROR = "✖"
ICON_DEPRECATED = "🚫"
ICON_SHIELD = "🛡️"

# Default Unicode Box borders
BORDER_CHARS = {
    "top_left": "┌", "horizontal": "─", "top_join": "┬", "top_right": "┐",
    "mid_left": "├", "mid_join": "┼", "mid_right": "┤",
    "bot_left": "└", "bot_join": "┴", "bot_right": "┘",
    "vertical": "│"
}

# Regex for parsing semantic version strings

# Cached Regex patterns for performance
RE_SEMVER_ALPHA = re.compile(r'([a-zA-Z]+.*)$')
RE_SEMVER_DIGITS = re.compile(r'\d+')

SEMVER_REGEX = re.compile(
    r'^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)'
    r'(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
    r'(?:\+(?P<buildmetadata>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$'
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
        except Exception:
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
            "top_left": "+", "horizontal": "-", "top_join": "+", "top_right": "+",
            "mid_left": "+", "mid_join": "+", "mid_right": "+",
            "bot_left": "+", "bot_join": "+", "bot_right": "+",
            "vertical": "|"
        }


DEBUG_MODE = False

def _is_safe_path(base_dir, target_path):
    """
    Verifies that target_path resolves within the base_dir directory to prevent Path Traversal.
    """
    if not base_dir or not target_path:
        return False
    real_base = os.path.realpath(base_dir)
    real_target = os.path.realpath(target_path)
    if real_target == real_base:
        return True
    base_prefix = real_base if real_base.endswith(os.path.sep) else real_base + os.path.sep
    return real_target.startswith(base_prefix)

def _detect_xml_encoding(content):
    """
    Sniffs the encoding of XML bytes based on BOM or the first '<' character alignment.
    Returns the name of the encoding as a string.
    """
    if not content:
        return "utf-8"

    # 1. Check for standard Byte Order Marks (BOM)
    if content.startswith(b'\xef\xbb\xbf'):
        return 'utf-8-sig'
    if content.startswith(b'\xff\xfe\x00\x00'):
        return 'utf-32-le'
    if content.startswith(b'\x00\x00\xfe\xff'):
        return 'utf-32-be'
    if content.startswith(b'\xff\xfe'):
        return 'utf-16'  # Python's utf-16 auto-detects and removes BOM
    if content.startswith(b'\xfe\xff'):
        return 'utf-16'  # Python's utf-16 auto-detects and removes BOM

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
        if idx % 4 == 3 and idx >= 3 and content[idx-3:idx] == b'\x00\x00\x00':
            return 'utf-32-be'
        # UTF-32-LE: '<' is U+3C000000 (0x3c 0x00 0x00 0x00), so idx % 4 == 0.
        if idx % 4 == 0 and idx + 3 < len(content) and content[idx+1:idx+4] == b'\x00\x00\x00':
            return 'utf-32-le'
        # UTF-16-BE: '<' is U+003C (0x00 0x3c), so idx % 2 == 1.
        if idx % 2 == 1 and idx >= 1 and content[idx-1] == 0x00:
            return 'utf-16-be'
        # UTF-16-LE: '<' is U+3C00 (0x3c 0x00), so idx % 2 == 0.
        if idx % 2 == 0 and idx + 1 < len(content) and content[idx+1] == 0x00:
            return 'utf-16-le'

    return "utf-8"

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
            raise ValueError(f"XML parsing rejected: Node depth exceeds limit of {self.max_depth}")
        self.total_size += len(name)
        for k, v in attrs.items():
            self.total_size += len(k) + len(v)
        if self.total_size > self.max_expanded_size:
            raise ValueError("XML parsing rejected: Expanded data size limit exceeded")
        element = ET.Element(name, attrs)
        if not self.stack:
            self.root = element
        else:
            self.stack[-1].append(element)
        self.stack.append(element)

    def end_element(self, name):
        self.depth -= 1
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

def parse_secure_xml(content, max_depth=15, max_expanded_size=10*1024*1024):
    builder = SecureXMLBuilder(max_depth, max_expanded_size)
    
    # 3. Asegurar que el manejo de encodings mediante sniffing de BOM se mantenga intacto
    if isinstance(content, bytes):
        encoding = _detect_xml_encoding(content)
        try:
            content_str = content.decode(encoding, errors='replace')
        except Exception:
            content_str = content.decode('latin-1', errors='replace')
    else:
        content_str = content

    content_bytes = content_str.encode("utf-8")

    parser = xml.parsers.expat.ParserCreate(encoding="utf-8")
    parser.StartElementHandler = builder.start_element
    parser.EndElementHandler = builder.end_element
    parser.CharacterDataHandler = builder.char_data
    
    # 1 y 2. Delegar la validación a los handlers de Expat y lanzar ValueError inmediato
    def forbid_doctype(*args, **kwargs):
        raise ValueError("XML parsing rejected: XML contains forbidden DOCTYPE declarations.")
        
    def forbid_entity(*args, **kwargs):
        raise ValueError("XML parsing rejected: XML contains forbidden Entity declarations.")

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
    with open(source, 'rb') as f:
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
        elif exc.code in (408, 504):
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

def safe_urlopen(req, timeout=10, max_retries=3, backoff=0.5):
    """Safely opens a URL with retries, exponential backoff, and default headers."""
    # 1. Extraer la URL de forma segura
    if isinstance(req, str):
        url_str = req
    elif isinstance(req, urllib.request.Request):
        url_str = req.full_url
    elif hasattr(req, "full_url"):
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
    if scheme not in ("https", "http"):
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
            # Do not retry on client errors (4xx) except possibly rate limits (429)
            if e.code == 404:
                raise e
            if e.code < 500 and e.code != 429:
                raise e
            last_err = e
        except (urllib.error.URLError, ConnectionResetError, TimeoutError, OSError) as e:
            last_err = e
            
        if attempt < max_retries - 1:
            time.sleep(backoff * (2 ** attempt))
            
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
        
    parts1 = p1.split('.')
    parts2 = p2.split('.')
    
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

def parse_semver(version_str):
    """Parses a version string into (epoch, major, minor, patch, revision, prerelease)."""
    if not version_str:
        return (0, 0, 0, 0, 0, '')
    
    clean_str = version_str.strip()
    if clean_str.lower().startswith('v'):
        clean_str = clean_str[1:]
        
    if '+' in clean_str:
        clean_str = clean_str.split('+', 1)[0]
        
    epoch = 0
    if '!' in clean_str:
        parts = clean_str.split('!', 1)
        try:
            epoch = int(parts[0])
        except ValueError:
            epoch = 0
        clean_str = parts[1]
        
    prerelease = ''
    if '-' in clean_str:
        clean_str, prerelease = clean_str.split('-', 1)
    else:
        m = RE_SEMVER_ALPHA.search(clean_str)
        if m:
            qualifier = m.group(1).lower()
            if any(q in qualifier for q in ('a', 'b', 'rc', 'cr', 'dev', 'alpha', 'beta', 'preview')):
                start_idx = m.start()
                prerelease = clean_str[start_idx:]
                clean_str = clean_str[:start_idx]
                if clean_str.endswith('.'):
                    clean_str = clean_str[:-1]
                    
    if prerelease:
        p_lower = prerelease.lower()
        if not any(q in p_lower for q in ('a', 'b', 'rc', 'cr', 'dev', 'alpha', 'beta', 'preview', 'snapshot', 'milestone', 'pre')):
            prerelease = ''
            
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
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Kevlar Dependency Scanner)"})
        with safe_urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            for k, v in data.items():
                major = k[1:] if k.startswith("v") else k
                schedule[major] = {
                    "maintenance": v.get("maintenance", "N/A"),
                    "end": v.get("end", "N/A")
                }
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning fetching Node.js release schedule: {e}{COLOR_RESET}")
        
    return schedule

def satisfy_term(version_str, term):
    try:
        term = term.strip()
        if not term or term in ("*", "x"):
            return True
            
        op = ""
        for possible_op in (">=", "<=", ">", "<", "^", "~", "=="):
            if term.startswith(possible_op):
                op = possible_op
                break
        if not op and term.startswith("="):
            op = "="
            
        ver_part = term[len(op):] if op else term
        
        _, v_maj, v_min, v_pat, _, _ = parse_semver(version_str)
        
        if ver_part.endswith(".x") or ver_part.endswith(".*"):
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
        elif op in ("=", "==", ""):
            return compare_versions(version_str, ver_part) == 0
        elif op == "^":
            if compare_versions(version_str, ver_part) < 0:
                return False
            if t_maj > 0:
                return v_maj == t_maj
            elif t_min > 0:
                return v_maj == 0 and v_min == t_min
            else:
                return v_maj == 0 and v_min == 0 and v_pat == t_pat
        elif op == "~":
            parts_count = len(ver_part.split("."))
            if compare_versions(version_str, ver_part) < 0:
                return False
            if parts_count >= 2:
                return v_maj == t_maj and v_min == t_min
            else:
                return v_maj == t_maj
    except Exception:
        return True
    return True

def check_semver_satisfies(version_str, range_str):
    """Checks if version_str satisfies range_str according to semver rules."""
    if not range_str or range_str.strip() in ("*", "x", "any"):
        return True
    
    range_str = re.sub(r'([><=^~])\s+', r'\1', range_str.strip())
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
                
                if DEBUG_MODE:
                    print(f"\n{COLOR_RED}{ICON_ERROR} Error checking {name}: {e}{COLOR_RESET}")
                    traceback.print_exc(file=sys.stdout)
                else:
                    print(f"\n{COLOR_RED}{ICON_ERROR} Error checking {name}: {sanitized_msg}{COLOR_RESET}")
                    
                installed = target_pkg.get("installed", [])
                versions_to_check = installed if installed else [target_pkg.get("declared")]
                for ver_str in versions_to_check:
                    results.append({
                        "name": name,
                        "declared": ver_str,
                        "installed": ver_str,
                        "latest": "unknown",
                        "status": "error",
                        "deprecated": False,
                        "error": sanitized_msg
                    })
            
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
        return "error", None, "We cannot recommend a valid version at this time as there is no internet connection.", "unknown"
        
    today = date.today()
    
    # Sort and filter known major versions from the schedule keys
    test_majors = sorted(
        [k for k in schedule.keys() if k.isdigit()],
        key=int
    )
    test_majors.append(FUTURE_MAJOR_PLACEHOLDER)
    
    # Filter for active (non-EOL) even major versions
    active_even_majors = [
        major for major in test_majors
        if major != FUTURE_MAJOR_PLACEHOLDER
        and int(major) % 2 == 0
        and not _is_major_version_eol(major, schedule, today)
    ]
    latest_lts = active_even_majors[-1] if active_even_majors else DEFAULT_FALLBACK_MAJOR
    
    if not constraint_str or constraint_str.strip() in ("*", "x", "any"):
        return "minor", f"Node.js engine constraint is wildcard or missing. Recommend specifying >={latest_lts}.0.0.", None, f">={latest_lts}.0.0"
        
    # Find all major versions satisfied by the constraint
    satisfied_majors = [
        major for major in test_majors
        if check_semver_satisfies(f"{major}.0.0", constraint_str)
    ]
    
    # Categorize satisfied major versions into EOL and supported
    eol_majors = [major for major in satisfied_majors if _is_major_version_eol(major, schedule, today)]
    supported_majors = [major for major in satisfied_majors if not _is_major_version_eol(major, schedule, today)]
    
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
        latest_stable = f"v{supported_even_majors[-1]}" if supported_even_majors else f"v{DEFAULT_FALLBACK_MAJOR}"
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
                        if re.match(r'^v?\d+', content):
                            return f"={content}", ".nvmrc"
                        return content, ".nvmrc"
        except Exception:
            pass
            
    node_ver_path = os.path.join(base_path, ".node-version")
    if os.path.exists(node_ver_path):
        try:
            with open(node_ver_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    content = content.split("#")[0].strip()
                    if content:
                        if re.match(r'^v?\d+', content):
                            return f"={content}", ".node-version"
                        return content, ".node-version"
        except Exception:
            pass
            
    return None, None

def classify_update(installed_str, latest_str):
    """Classifies the update difference between installed and latest version."""
    if installed_str == latest_str:
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
    if not latest_absolute or installed_ver == "0.0.0":
        return "up-to-date"
        
    abs_type = classify_update(installed_ver, latest_absolute)
    if abs_type == "major" and latest_same_major and latest_same_major != installed_ver:
        clean_inst = re.sub(r'^[^\d]*', '', installed_ver).strip()
        clean_same = re.sub(r'^[^\d]*', '', latest_same_major).strip()
        if clean_inst and clean_same and clean_inst != clean_same:
            same_major_type = classify_update(clean_inst, clean_same)
            if same_major_type in ("minor", "patch"):
                return f"{same_major_type}-major"
                
    return abs_type

def find_latest_same_major(installed_ver, all_versions):
    """Finds the latest version in all_versions that shares the same major version as installed_ver.
    Returns:
        (latest_same_major, latest_absolute)
    """
    if not installed_ver or not all_versions:
        return (None, None)
    
    # Strip common non-numeric prefix from installed version
    clean_inst = re.sub(r'^[^\d]*', '', installed_ver).split('+')[0]
    _, inst_major, _, _, _, inst_prerelease = parse_semver(clean_inst)
    installed_is_prerelease = bool(inst_prerelease)
    
    # Filter out prerelease versions if the installed version is stable
    filtered_versions = []
    for v in all_versions:
        clean_v = re.sub(r'^[^\d]*', '', v).split('+')[0]
        _, _, _, _, _, prerelease = parse_semver(clean_v)
        if not installed_is_prerelease and prerelease:
            continue
        filtered_versions.append(v)
        
    # If filtering left us with nothing, fall back to all versions
    if not filtered_versions:
        filtered_versions = all_versions
    
    # helper for sorting
    def semver_sort_key(v_str):
        clean = re.sub(r'^[^\d]*', '', v_str).split('+')[0]
        epoch, major, minor, patch, revision, prerelease = parse_semver(clean)
        is_stable = 1 if not prerelease else 0
        return (epoch, major, minor, patch, revision, is_stable, PrereleaseKey(prerelease))
        
    sorted_all = sorted(filtered_versions, key=semver_sort_key)
    if not sorted_all:
        return (None, None)
        
    latest_absolute = sorted_all[-1]
    
    same_major_versions = []
    for v in sorted_all:
        clean_v = re.sub(r'^[^\d]*', '', v).split('+')[0]
        _, v_major, _, _, _, _ = parse_semver(clean_v)
        if v_major == inst_major:
            same_major_versions.append(v)
            
    latest_same_major = same_major_versions[-1] if same_major_versions else None
    
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
        
    if url.startswith("git+"):
        url = url[4:]
    if url.startswith("git://"):
        url = "https://" + url[6:]
    elif url.startswith("git@"):
        url = url[4:]
        url = url.replace(":", "/")
        url = "https://" + url
    if url.endswith(".git"):
        url = url[:-4]
    url = url.replace("ssh://git@", "https://")
    url = url.rstrip("/")
    
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            if url:
                url = "https://" + url
            parsed = urllib.parse.urlparse(url)
            
        if parsed.scheme not in ("http", "https"):
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
            print(f"{COLOR_YELLOW}{ICON_WARN} Debug: Failed to resolve NPM repository for '{name}': {e}{COLOR_RESET}")
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
            tag_local = elem.tag.split('}')[-1]
            if tag_local == 'repository':
                val = elem.attrib.get('url')
                if val:
                    repo_url = val
            elif tag_local == 'projectUrl':
                if elem.text:
                    proj_url = elem.text.strip()
        if repo_url:
            return clean_repo_url(repo_url)
        if proj_url:
            return clean_repo_url(proj_url)
    except Exception as e:
        if DEBUG_MODE:
            print(f"{COLOR_YELLOW}{ICON_WARN} Debug: Failed to resolve NuGet repository for '{name}' (version {version}): {e}{COLOR_RESET}")
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
            tag_local = elem.tag.split('}')[-1]
            if tag_local == 'scm':
                for child in elem:
                    child_tag = child.tag.split('}')[-1]
                    if child_tag == 'url':
                        scm_url = child.text
            elif tag_local == 'url':
                if elem.text:
                    proj_url = elem.text
        return clean_repo_url(scm_url or proj_url)
    except Exception as e:
        if DEBUG_MODE:
            print(f"{COLOR_YELLOW}{ICON_WARN} Debug: Failed to resolve Maven repository for '{group_path}:{artifact_id}' (version {version}) from {registry_url}: {e}{COLOR_RESET}")
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
        raw_bytes = codecs.decode(hex_str.strip(), 'hex')
        b64_bytes = base64.b64encode(raw_bytes)
        return "sha1-" + b64_bytes.decode('utf-8')
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

def parse_yarn_lock(filepath):
    """Parses yarn.lock to extract resolved versions and their parent relations.
    Returns:
        tuple: (resolved, parents, integrity) where integrity is (name, version) -> integrity_str
    """
    resolved = {}
    parents = {}
    integrity_dict = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            current_names = []
            current_version = None
            current_integrity = None
            in_dependencies = False
            
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                
                indent_len = len(line) - len(line.lstrip())
                
                if indent_len == 0:
                    if current_names and current_version:
                        for name in current_names:
                            if current_integrity:
                                integrity_dict[(name, current_version)] = current_integrity
                    in_dependencies = False
                    current_names = []
                    current_version = None
                    current_integrity = None
                    header = stripped.rstrip(":")
                    
                    parts = []
                    current_part = []
                    in_quotes = False
                    for char in header:
                        if char == '"':
                            in_quotes = not in_quotes
                        elif char == ',' and not in_quotes:
                            parts.append("".join(current_part).strip())
                            current_part = []
                        else:
                            current_part.append(char)
                    if current_part:
                        parts.append("".join(current_part).strip())
                    
                    for part in parts:
                        part = part.strip('"')
                        if "@" in part:
                            if part.startswith("@"):
                                name_part = part[1:]
                                if "@" in name_part:
                                    pkg_name = "@" + name_part.rsplit("@", 1)[0]
                                else:
                                    pkg_name = part
                            else:
                                pkg_name = part.rsplit("@", 1)[0]
                        else:
                            pkg_name = part
                        
                        if pkg_name.startswith("npm:"):
                            pkg_name = pkg_name[4:]
                        current_names.append(pkg_name)
                        
                elif indent_len > 0:
                    if stripped.startswith("version ") or stripped.startswith("version:"):
                        ver_val = stripped.split(" ", 1)[-1] if " " in stripped else stripped.split(":", 1)[-1]
                        ver_val = ver_val.strip().strip('"').strip(':').strip()
                        current_version = ver_val
                        for name in current_names:
                            resolved.setdefault(name, set()).add(ver_val)
                    elif stripped.startswith("integrity ") or stripped.startswith("integrity:"):
                        integrity_val = stripped.split(" ", 1)[-1] if " " in stripped else stripped.split(":", 1)[-1]
                        integrity_val = integrity_val.strip().strip('"').strip(':').strip()
                        current_integrity = integrity_val
                    elif stripped.startswith("dependencies:") or stripped.startswith("optionalDependencies:") or stripped.startswith("peerDependencies:"):
                        in_dependencies = True
                    elif in_dependencies and indent_len >= 4:
                        dep_line = stripped
                        if ":" in dep_line:
                            dep_name = dep_line.split(":", 1)[0].strip().strip('"')
                        else:
                            dep_name = dep_line.split(" ", 1)[0].strip().strip('"')
                        if dep_name:
                            for name in current_names:
                                parents.setdefault(dep_name, set()).add(name)
                    
                    if indent_len == 2 and not (stripped.startswith("dependencies:") or stripped.startswith("optionalDependencies:") or stripped.startswith("peerDependencies:")):
                        in_dependencies = False
                        
            if current_names and current_version:
                for name in current_names:
                    if current_integrity:
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
                if not stripped or stripped.startswith("#") or stripped == "---" or stripped == "...":
                    continue
                
                indent = len(line) - len(line.lstrip())
                
                # Maintain the indentation stack: pop states that are at the same or deeper indentation
                while stack and indent <= stack[-1][0]:
                    stack.pop()
                
                current_state = stack[-1][1] if stack else 'ROOT'
                current_pkg = None
                current_version = None
                for item in reversed(stack):
                    if item[1] == 'PACKAGE_BODY' and item[2]:
                        current_pkg, current_version = item[2]
                        break
                
                # Check transition out/in of the packages block at root level
                if stripped.startswith("packages:"):
                    stack.append((indent, 'PACKAGES', None))
                    continue
                
                if current_state == 'PACKAGES':
                    # We are expecting package definitions as keys, e.g., '/direct-dep@1.0.1:'
                    raw_pkg = stripped.rstrip(":").strip("'\"")
                    if raw_pkg.startswith("/"):
                        raw_pkg = raw_pkg[1:]
                    if "/" in raw_pkg and not raw_pkg.startswith("@"):
                        first_part = raw_pkg.split("/", 1)[0]
                        if "." in first_part or "localhost" in first_part:
                            raw_pkg = raw_pkg.split("/", 1)[1]
                            
                    pkg_name = None
                    version = None
                    
                    if "@" in raw_pkg:
                        if raw_pkg.startswith("@"):
                            parts = raw_pkg[1:].rsplit("@", 1)
                            if len(parts) == 2:
                                pkg_name = "@" + parts[0]
                                version = parts[1]
                        else:
                            parts = raw_pkg.rsplit("@", 1)
                            if len(parts) == 2:
                                pkg_name = parts[0]
                                version = parts[1]
                                
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
                    
                    if pkg_name and version:
                        resolved.setdefault(pkg_name, set()).add(version)
                        # Push this package's context onto the stack
                        stack.append((indent, 'PACKAGE_BODY', (pkg_name, version)))
                
                elif current_state == 'PACKAGE_BODY':
                    # Inside a package block. We check for integrity and dependency subsections.
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
                                
                    if stripped.startswith("dependencies:") or stripped.startswith("optionalDependencies:") or stripped.startswith("peerDependencies:"):
                        stack.append((indent, 'DEPENDENCIES', None))
                
                elif current_state == 'DEPENDENCIES':
                    # We are in a list of dependencies under a package.
                    # Each line is: dependency_name: version
                    if ":" in stripped:
                        dep_name, dep_ver = stripped.split(":", 1)
                        dep_name = dep_name.strip().strip("'\"")
                        if dep_name and current_pkg:
                            parents.setdefault(dep_name, set()).add(current_pkg)
                            
        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean, integrity_dict
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading pnpm-lock.yaml: {e}{COLOR_RESET}")
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
            "engines": engines
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
            for pkg_path in data["packages"].keys():
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
                    for child_name in all_deps.keys():
                        parents.setdefault(child_name, set()).add(pkg_name)
                        
            # Root package dependencies
            root_info = data["packages"].get("") or {}
            root_deps = {
                **root_info.get("dependencies", {}),
                **root_info.get("devDependencies", {}),
                **root_info.get("peerDependencies", {}),
                **root_info.get("optionalDependencies", {})
            }
            for child_name in root_deps.keys():
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
                    
                    if "dependencies" in pkg_info and isinstance(pkg_info["dependencies"], dict):
                        recurse_v1_deps(pkg_info["dependencies"], pkg_name)
                        
            recurse_v1_deps(data["dependencies"])
            
        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean, integrity_dict, direct_versions
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading package-lock.json: {e}{COLOR_RESET}")
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
            targets.append({
                "name": name,
                "declared": declared,
                "installed": installed
            })
    else:
        if not pkg_data:
            print(f"{COLOR_RED}{ICON_ERROR} Cannot check direct dependencies: package.json is missing.{COLOR_RESET}")
            return []
            
        for name, declared in sorted(pkg_data["all_direct"].items()):
            installed = lock_data.get(name, [])
            targets.append({
                "name": name,
                "declared": declared,
                "installed": installed
            })
            
    return targets

def find_direct_installed_version(pkg_name, declared_constraint, installed_versions, direct_versions_from_lock=None):
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
            satisfying = [v for v in installed_versions if check_semver_satisfies(v, declared_constraint)]
            if len(satisfying) == 1:
                return satisfying[0]
            elif len(satisfying) > 1:
                return max(satisfying, key=parse_semver)
        except Exception:
            pass
            
    # Fallback 2: The highest installed version
    try:
        return max(installed_versions, key=parse_semver)
    except Exception:
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
            v.startswith("file:") or 
            v.startswith("link:") or 
            v.startswith("portal:") or 
            v.startswith("workspace:") or
            v.startswith("./") or
            v.startswith("../") or
            v.startswith("/")
        )
        
    versions_to_check = installed_versions if installed_versions else [declared]
    results = []
    
    try:
        # Properly URL-encode scoped packages (e.g. @babel/core -> @babel%2Fcore)
        if name.startswith('@'):
            parts = name.split('/')
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
                results.append({
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
                    "registry_checksums": []
                })
                continue
                
            # Strip ranges prefixes to get base version for check
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            ver_meta = all_versions_meta.get(clean_ver) or all_versions_meta.get(ver_str) or {}
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
                
                reg_hashes = [h.strip().lower() for h in reg_integrity.split() if h.strip()]
                if reg_shasum:
                    reg_shasum_b64 = hex_to_base64(reg_shasum)
                    if reg_shasum_b64:
                        reg_hashes.append(reg_shasum_b64.lower())
                        
                if reg_hashes and lock_clean not in reg_hashes:
                    mismatch = True
            
            # Find latest same major and absolute latest
            latest_same_major, latest_absolute = find_latest_same_major(clean_ver, all_versions)
            if latest_version:
                latest_absolute = latest_version
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            update_type = determine_update_type(clean_ver, latest_same_major, latest_absolute)
                
            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in ("major", "minor-major", "patch-major"):
                repo_url = resolve_npm_repo(name)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "registry_checksums": reg_hashes
            })
            
    except urllib.error.HTTPError as e:
        if e.code == 404:
            for ver_str in versions_to_check:
                results.append({
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
                    "registry_checksums": []
                })
        else:
            error_msg = f"HTTP {e.code}"
            for ver_str in versions_to_check:
                results.append({
                    "name": name,
                    "declared": declared,
                    "installed": ver_str,
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": error_msg,
                    "mismatch_checksum": False,
                    "lockfile_checksum": target.get("integrity", {}).get(ver_str),
                    "registry_checksums": []
                })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": str(e),
                "mismatch_checksum": False,
                "lockfile_checksum": target.get("integrity", {}).get(ver_str),
                "registry_checksums": []
            })
            
    return results

def check_all_targets(targets, max_workers):
    """Executes checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(targets, check_npm_package, f"{COLOR_GRAY}[Progress: NPM check]", max_workers)

# ==============================================================================
# OSV Vulnerability Scanning Logic
# ==============================================================================

def check_osv_vulnerabilities(targets, ecosystem, max_workers=10):
    """Checks vulnerabilities for all targets using OSV querybatch API.
    Returns a dict mapping (package_name, version) -> list of hydrated vulnerability dicts.
    """
    print(f"{COLOR_BOLD}{COLOR_CYAN}Querying OSV vulnerability database...{COLOR_RESET}\n")
    
    queries = []
    query_mapping = []
    
    for t in targets:
        name = t["name"]
        declared = t["declared"]
        installed_versions = t["installed"]
        
        versions_to_check = installed_versions if installed_versions else [declared]
        for ver_str in versions_to_check:
            # Clean range prefix symbols
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            queries.append({
                "package": {
                    "name": name,
                    "ecosystem": ecosystem
                },
                "version": clean_ver
            })
            query_mapping.append((name, ver_str, clean_ver))
            
    if not queries:
        return {}
        
    results_list = []
    chunk_size = 1000
    total_queries = len(queries)
    for i in range(0, total_queries, chunk_size):
        chunk_queries = queries[i:i + chunk_size]
        current_count = min(i + chunk_size, total_queries)
        sys.stdout.write(f"\r{COLOR_GRAY}[OSV] Sending batch query: {current_count}/{total_queries} packages...{COLOR_RESET}\033[K")
        sys.stdout.flush()
        try:
            url = URL_OSV_QUERYBATCH
            req = urllib.request.Request(
                url, 
                data=json.dumps({"queries": chunk_queries}).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            
            with safe_urlopen(req, timeout=15) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                
            results_list.extend(res_data.get("results", []))
        except Exception as e:
            sys.stdout.write("\n")
            print(f"{COLOR_RED}{ICON_ERROR} Failed to query OSV database batch: {e}{COLOR_RESET}")
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
        
        sys.stdout.write(f"\r{COLOR_GRAY}[OSV] Hydrating in-memory structures: {i + 1}/{total_results} packages...{COLOR_RESET}\033[K")
        sys.stdout.flush()
        
        vulns = res.get("vulns", [])
        
        # Hydrate subsequent pages if next_page_token is present
        next_page_token = res.get("next_page_token")
        while next_page_token:
            try:
                url = "https://api.osv.dev/v1/query"
                payload = {
                    "package": {
                        "name": name,
                        "ecosystem": ecosystem
                    },
                    "version": clean_ver,
                    "page_token": next_page_token
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
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
        
    orphaned_ids = sorted([vid for vid in all_vuln_ids if vid not in hydrated_details or "summary" not in hydrated_details[vid]])
    
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
                return vuln_id, {"id": vuln_id, "summary": f"Failed to fetch details: {e}", "severity": "UNKNOWN"}
                
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_vuln_detail, vid): vid for vid in orphaned_ids}
            for future in as_completed(futures):
                completed += 1
                vid = futures[future]
                sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total_orphaned}] Fetching missing advisory details for {vid}...{COLOR_RESET}\033[K")
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
            # Determine severity
            severity = "UNKNOWN"
            if "severity" in vuln_data and isinstance(vuln_data["severity"], list):
                for sev in vuln_data["severity"]:
                    if sev.get("type") in ("CVSS_V4", "CVSS_V3", "CVSS_V2"):
                        score = sev.get('score')
                        if score:
                            score_str = str(score)
                            if score_str.startswith("CVSS"):
                                severity = score_str
                            else:
                                prefix = "CVSS:4.0/" if sev.get("type") == "CVSS_V4" else ("CVSS:3.0/" if sev.get("type") == "CVSS_V3" else "CVSS:2.0/")
                                severity = f"{prefix}{score_str}"
                        break
            if severity == "UNKNOWN":
                db_spec = vuln_data.get("database_specific")
                if db_spec and isinstance(db_spec, dict):
                    severity = db_spec.get("severity") or "UNKNOWN"
            
            summary = vuln_data.get("summary")
            details = vuln_data.get("details", "")
            
            # If severity is UNKNOWN or summary is missing/generic, try to resolve via aliases already in hydrated_details
            if (severity == "UNKNOWN" or not summary or summary == "No summary provided") and "aliases" in vuln_data:
                for alias in vuln_data["aliases"]:
                    alias_data = hydrated_details.get(alias)
                    if alias_data:
                        if severity == "UNKNOWN":
                            if "severity" in alias_data and isinstance(alias_data["severity"], list):
                                for sev in alias_data["severity"]:
                                    if sev.get("type") in ("CVSS_V4", "CVSS_V3", "CVSS_V2"):
                                        score = sev.get('score')
                                        if score:
                                            score_str = str(score)
                                            if score_str.startswith("CVSS"):
                                                severity = score_str
                                            else:
                                                prefix = "CVSS:4.0/" if sev.get("type") == "CVSS_V4" else ("CVSS:3.0/" if sev.get("type") == "CVSS_V3" else "CVSS:2.0/")
                                                severity = f"{prefix}{score_str}"
                                        break
                            if severity == "UNKNOWN":
                                db_spec = alias_data.get("database_specific")
                                if db_spec and isinstance(db_spec, dict):
                                    severity = db_spec.get("severity") or "UNKNOWN"
                        
                        if not summary or summary == "No summary provided":
                            summary = alias_data.get("summary")
                        if not details:
                            details = alias_data.get("details", "")
            
            vuln_list.append({
                "id": vid,
                "summary": summary or "No summary provided",
                "severity": severity,
                "details": details or ""
            })
        
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "unknown": 0
        }
        vuln_list.sort(key=lambda v: severity_order.get(get_severity_level(v), 0), reverse=True)
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
        raise ValueError(f"Metadata version '{version}' is invalid. Must match pattern 'X.Y' or 'X.Y.Z'.")
        
    # Validate last_modified date
    last_mod_str = metadata["last_modified"].strip()
    try:
        datetime.strptime(last_mod_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"Metadata 'last_modified' '{last_mod_str}' is invalid. Must be in 'YYYY-MM-DD' format.")
        
    # Validate suppressions
    suppressions = data["suppressions"]
    if not isinstance(suppressions, list):
        raise ValueError("'suppressions' must be a JSON array.")
        
    allowed_reasons = {
        "NOT_AFFECTED_BY_VULNERABILITY",
        "VULNERABILITY_MITIGATED_BY_ENVIRONMENT",
        "COMPENSATING_CONTROL_IMPLEMENTED",
        "FALSE_POSITIVE",
        "ACCEPTED_TEMPORARY_RISK"
    }
    
    for idx, rule in enumerate(suppressions):
        if not isinstance(rule, dict):
            raise ValueError(f"Suppression rule at index {idx} must be a JSON object.")
            
        # Check required fields
        required_fields = ["id", "package", "reason", "justification", "expires_at"]
        for req_field in required_fields:
            if req_field not in rule:
                raise ValueError(f"Suppression rule at index {idx} is missing required field: '{req_field}'")
            if not isinstance(rule[req_field], str) or not rule[req_field].strip():
                raise ValueError(f"Suppression rule field '{req_field}' at index {idx} must be a non-empty string.")
                
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
                        raise ValueError(f"Optional field '{opt_field}' at index {idx} must be a non-empty string if specified.")

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
            print(f"{COLOR_RED}{ICON_ERROR} Suppress file not found: {suppress_path}{COLOR_RESET}")
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
        
    print(f"{COLOR_BOLD}{COLOR_CYAN}Loading suppressions from {file_to_load}...{COLOR_RESET}")
    try:
        with open(file_to_load, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to parse suppressions file: {e}{COLOR_RESET}")
        sys.exit(1)
        
    try:
        validate_suppressions_schema(data)
    except ValueError as e:
        print(f"{COLOR_RED}{ICON_ERROR} Suppressions file schema validation failed: {e}{COLOR_RESET}")
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
            print(f"{COLOR_YELLOW}{ICON_WARN} Suppression rule for package '{rule['package']}' (vuln: '{rule['id']}') expired on {expires_at_str} and was discarded.{COLOR_RESET}")
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
                print(f"{COLOR_GRAY}[SUPPRESSED] Ignored {vuln['id']} for package '{r['name']}'{tech_suffix} (Reason: {matched_rule['reason']}){COLOR_RESET}")
            else:
                active_vulns.append(vuln)
                
        r["vulnerabilities"] = active_vulns
        r["suppressed_vulnerabilities"] = suppressed_vulns
        
    if suppressed_count > 0:
        print(f"\n{COLOR_GREEN}{ICON_OK} Successfully suppressed {suppressed_count} vulnerability alerts.{COLOR_RESET}\n")

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
            if p == "root":
                continue
            if p in direct_packages:
                direct_parents.add(p)
            else:
                queue.append(p)
                
    return direct_parents

def run_npm_checker(args):
    """Main orchestrator for npm checker."""
    pkg_file, lock_file = find_npm_files(args.path)
    
    if not pkg_file and not lock_file:
        print(f"{COLOR_RED}{ICON_ERROR} No package.json or lockfile found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    pkg_data = None
    if pkg_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading package.json...{COLOR_RESET}")
        pkg_data = parse_package_json(pkg_file)
        
    lock_data = {}
    parents_data = {}
    integrity_data = {}
    direct_versions_lock = {}
    if lock_file:
        basename = os.path.basename(lock_file)
        if basename == "package-lock.json":
            print(f"{COLOR_GRAY}{ICON_INFO} Reading package-lock.json...{COLOR_RESET}")
            lock_data, parents_data, integrity_data, direct_versions_lock = parse_package_lock(lock_file)
        elif basename == "yarn.lock":
            print(f"{COLOR_GRAY}{ICON_INFO} Reading yarn.lock...{COLOR_RESET}")
            lock_data, parents_data, integrity_data = parse_yarn_lock(lock_file)
        elif basename == "pnpm-lock.yaml":
            print(f"{COLOR_GRAY}{ICON_INFO} Reading pnpm-lock.yaml...{COLOR_RESET}")
            lock_data, parents_data, integrity_data = parse_pnpm_lock(lock_file)
        
    targets = build_check_targets(pkg_data, lock_data, args.all)
    for t in targets:
        t_integrity = {}
        for ver in t["installed"]:
            key = (t["name"], ver)
            if key in integrity_data:
                t_integrity[ver] = integrity_data[key]
        t["integrity"] = t_integrity
    
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_targets(targets, args.concurrent)
    
    # Identify and isolate direct vs transitive results for npm packages
    # We want to clear the 'declared' constraint for transitive versions of a package
    # so they are not flagged as configuration drift and are correctly shown as transitive in the report.
    if pkg_data and "all_direct" in pkg_data:
        # Group result indices by package name
        by_name = {}
        for idx, r in enumerate(results):
            if not r.get("is_engine", False):
                by_name.setdefault(r["name"], []).append(idx)
                
        for name, indices in by_name.items():
            if name in pkg_data["all_direct"] and len(indices) > 1:
                # We have multiple installed versions for a direct dependency.
                # Find which version is the direct install.
                declared_constraint = pkg_data["all_direct"][name]
                installed_versions = [results[idx]["installed"] for idx in indices]
                
                # Get direct version
                direct_ver = find_direct_installed_version(
                    name, declared_constraint, installed_versions, 
                    direct_versions_from_lock=direct_versions_lock
                )
                
                # Clear 'declared' for all other versions of this package
                for idx in indices:
                    if results[idx]["installed"] != direct_ver:
                        results[idx]["declared"] = None
    
    # Check integrity checksums
    for r in results:
        r["missing_checksum"] = False
        r["weak_checksum"] = False
        if r.get("is_engine", False):
            continue
            
        if lock_file:
            key = (r["name"], r["installed"])
            if key in integrity_data and integrity_data[key]:
                integrity_str = integrity_data[key].lower()
                if "sha512-" in integrity_str or "sha256-" in integrity_str:
                    pass
                elif "sha1-" in integrity_str:
                    r["weak_checksum"] = True
                else:
                    r["missing_checksum"] = True
            else:
                r["missing_checksum"] = True

    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["npm"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
        # Attach vulns back to results
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []
            
    # Check Node.js version if applicable
    node_constraint, _source = find_node_constraint(args.path, pkg_data)
    if node_constraint:
        status, deprecated_msg, error_msg, recommendation = analyze_node_constraint(node_constraint)
            
        results.append({
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
            "is_engine": True
        })
            
    # Resolve transitive dependency parents
    direct_packages = set(pkg_data["all_direct"].keys()) if pkg_data else set()
    for r in results:
        if not r.get("is_engine", False):
            direct_parents = find_direct_parents(r["name"], parents_data, direct_packages)
            r["required_by"] = sorted(list(direct_parents - {r["name"]}))
        else:
            r["required_by"] = []
            
    elapsed = time.time() - start_time
    
    return results, pkg_data, elapsed

# ==============================================================================
# PIP Checker Logic
# ==============================================================================

def parse_requirements_txt(filepath):
    """Parses requirements.txt to extract dependencies and parent traces."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        dependencies = {}
        parents = {}
        
        last_pkg = None
        pkg_re = re.compile(
            r'^\s*([A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?)\s*'
            r'(?:(==|>=|<=|~=|!=|>|<|=)\s*([A-Za-z0-9_.!+*-]+)(?:\s*,\s*.*)?)?'
        )
        
        for line in lines:
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
            elif "#" in line and not any(scheme in line for scheme in ("http://", "https://", "git+")):
                parts = line.split("#", 1)
                stripped_line = parts[0].strip()
                comment = parts[1].strip()
                
            if stripped_line.startswith("-"):
                continue
                
            match = pkg_re.match(stripped_line)
            if match:
                pkg_name = match.group(1)
                if "[" in pkg_name:
                    pkg_name = pkg_name.split("[")[0]
                    
                op = match.group(2)
                ver = match.group(3)
                
                version_spec = f"{op}{ver}" if op and ver else ""
                dependencies[pkg_name] = version_spec or "*"
                last_pkg = pkg_name
                
                if comment.startswith("via"):
                    parent_part = comment[3:].strip()
                    for p in parent_part.split(","):
                        p_clean = p.strip()
                        if p_clean:
                            parents.setdefault(pkg_name, set()).add(p_clean)
                            
        return dependencies, {k: list(v) for k, v in parents.items()}
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Error reading requirements.txt: {e}{COLOR_RESET}")
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
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            # Check yanking (deprecation)
            files_list = releases.get(clean_ver) or releases.get(ver_str) or []
            yanked_reason = None
            for file_info in files_list:
                if isinstance(file_info, dict) and file_info.get("yanked"):
                    yanked_reason = file_info.get("yanked_reason") or "This release was yanked from PyPI."
                    break
                    
            # Find latest same major and absolute latest
            latest_same_major, latest_absolute = find_latest_same_major(clean_ver, all_versions)
            if latest_version:
                latest_absolute = latest_version
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            update_type = determine_update_type(clean_ver, latest_same_major, latest_absolute)
                
            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in ("major", "minor-major", "patch-major"):
                urls = info.get("project_urls") or {}
                raw_url = None
                for key in ["Source", "Repository", "Code", "Homepage"]:
                    for k, v in urls.items():
                        if key.lower() in k.lower() and v and is_github_url(clean_repo_url(v)):
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
                    releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "releases_url": releases_url
            })
            
    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": error_msg
            })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": str(e)
            })
            
    return results

def check_all_pip_targets(targets, max_workers):
    """Executes PyPI checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(targets, check_pypi_package, f"{COLOR_GRAY}[Progress: PyPI check]", max_workers)

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
                if stripped.startswith("[[") or (stripped.startswith("[") and not stripped.startswith("[package.dependencies]")):
                    in_deps = False
                if stripped.startswith("[package.dependencies]"):
                    in_deps = True
                    continue
                    
                if not in_deps:
                    if stripped.startswith("name ="):
                        name = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                    elif stripped.startswith("version ="):
                        version = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                else:
                    if "=" in stripped:
                        dep_name = stripped.split("=", 1)[0].strip().strip('"').strip("'")
                        if dep_name and name:
                            parents.setdefault(dep_name, set()).add(name)
                            
            if name and version:
                resolved.setdefault(name, set()).add(version)
                
        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading poetry.lock: {e}{COLOR_RESET}")
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
                if stripped.startswith("[[") or (stripped.startswith("[") and not stripped.startswith("dependencies =")):
                    in_deps = False
                if stripped.startswith("dependencies = ["):
                    in_deps = True
                    continue
                    
                if not in_deps:
                    if stripped.startswith("name ="):
                        name = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                    elif stripped.startswith("version ="):
                        version = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                else:
                    if stripped == "]":
                        in_deps = False
                    else:
                        item = stripped.rstrip(",").strip().strip('"').strip("'")
                        if item:
                            match = re.match(r'^([a-zA-Z0-9\-_.]+)', item)
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
                    if version.startswith("=="):
                        version = version[2:]
                    resolved.setdefault(name, set()).add(version)
                    
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, {}
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading Pipfile.lock: {e}{COLOR_RESET}")
        return {}, {}

def parse_pyproject_toml(filepath):
    """Parses pyproject.toml to extract direct dependencies.
    Returns:
        dict: name -> version_specifier
    """
    dependencies = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        in_poetry_deps = False
        in_pep621_deps = False
        
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
                
            if stripped.startswith("[tool.poetry.dependencies]"):
                in_poetry_deps = True
                in_pep621_deps = False
                continue
            elif stripped.startswith("dependencies = ["):
                in_pep621_deps = True
                in_poetry_deps = False
                continue
            elif stripped.startswith("["):
                in_poetry_deps = False
                in_pep621_deps = False
                
            if in_poetry_deps:
                if "=" in stripped:
                    name = stripped.split("=", 1)[0].strip().strip('"').strip("'")
                    val = stripped.split("=", 1)[1].strip()
                    if name != "python":
                        if val.startswith("{"):
                            ver_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', val)
                            version = ver_match.group(1) if ver_match else "*"
                        else:
                            version = val.strip('"').strip("'")
                        dependencies[name] = version
            elif in_pep621_deps:
                if stripped == "]":
                    in_pep621_deps = False
                else:
                    item = stripped.rstrip(",").strip().strip('"').strip("'")
                    if item:
                        match = re.match(r'^([a-zA-Z0-9\-_.]+)(.*)$', item)
                        if match:
                            name = match.group(1)
                            spec = match.group(2).strip()
                            dependencies[name] = spec if spec else "*"
                            
        return dependencies
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading pyproject.toml: {e}{COLOR_RESET}")
        return {}

def run_pip_checker(args):
    """Main orchestrator for pip checker."""
    manifest_file, lock_file, tech_type = find_pip_files(args.path)
    
    if not manifest_file and not lock_file:
        print(f"{COLOR_RED}{ICON_ERROR} No requirements.txt, poetry.lock, Pipfile.lock, or pyproject.toml found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    direct_deps = {}
    lock_deps = {}
    parents_data = {}
    
    if tech_type == "poetry":
        print(f"{COLOR_GRAY}{ICON_INFO} Reading pyproject.toml (Poetry)...{COLOR_RESET}")
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
        direct_deps = {k: "*" for k in lock_deps.keys()}
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
            targets.append({
                "name": name,
                "declared": declared,
                "installed": versions
            })
    else:
        for name, declared in sorted(direct_deps.items()):
            versions = lock_deps.get(name, [])
            if not versions and declared and not any(c in declared for c in [">", "<", "~", "*", "^"]):
                clean_ver = declared[2:] if declared.startswith("==") else declared
                versions = [clean_ver]
            targets.append({
                "name": name,
                "declared": declared,
                "installed": versions
            })
            
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No Python packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_pip_targets(targets, args.concurrent)
    
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["pip"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
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
    
    pkg_data_deps = {k: v[0] if isinstance(v, list) and v else v for k, v in lock_deps.items()} if lock_deps else direct_deps
    
    return results, {"dependencies": pkg_data_deps, "devDependencies": {}, "all_direct": all_direct}, elapsed

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
                print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Directory.Packages.props: {e}{COLOR_RESET}")
                
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
        
    return {}

def parse_sln_file(sln_path):
    """Parses a .sln file to retrieve relative paths to all project files."""
    project_paths = []
    try:
        with open(sln_path, "r", encoding="utf-8-sig") as f:
            content = f.read()
            
        proj_re = re.compile(r'Project\([^)]+\)\s*=\s*"[^"]+"\s*,\s*"([^"]+)"')
        matches = proj_re.findall(content)
        sln_dir = os.path.dirname(os.path.abspath(sln_path))
        
        for m in matches:
            norm_path = m.replace("\\", "/")
            if norm_path.endswith((".csproj", ".vbproj", ".fsproj")):
                full_path = os.path.join(sln_dir, norm_path)
                if os.path.exists(full_path):
                    project_paths.append(full_path)
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading .sln file: {e}{COLOR_RESET}")
        
    return project_paths

def find_nuget_files(path):
    """Finds Solution file (.sln), MSBuild project files, and assets files."""
    sln_file = None
    manifests = []
    assets_files = []
    
    abs_path = os.path.abspath(path)
    if os.path.isfile(abs_path):
        if abs_path.endswith(".sln"):
            sln_file = abs_path
        elif abs_path.endswith((".csproj", ".vbproj", ".fsproj")) or abs_path.endswith("packages.config"):
            manifests = [abs_path]
    elif os.path.isdir(abs_path):
        sln_candidates = [os.path.join(abs_path, f) for f in os.listdir(abs_path) if f.endswith(".sln")]
        if sln_candidates:
            sln_file = sln_candidates[0]
        else:
            files = os.listdir(abs_path)
            for f in files:
                if f.endswith((".csproj", ".vbproj", ".fsproj")) or f == "packages.config":
                    manifests = [os.path.join(abs_path, f)]
                    break
                    
    if sln_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Solution file detected: {os.path.basename(sln_file)}{COLOR_RESET}")
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
            print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing packages.config: {e}{COLOR_RESET}")
            
    try:
        proj_files = [f for f in os.listdir(path) if f.endswith((".csproj", ".vbproj", ".fsproj"))]
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
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing project files: {e}{COLOR_RESET}")
        
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
        for _target_name, target_libs in targets.items():
            for lib_key, lib_info in target_libs.items():
                parts = lib_key.split("/")
                if len(parts) != 2:
                    continue
                parent_name = parts[0]
                
                deps = lib_info.get("dependencies", {})
                for child_name in deps.keys():
                    parents.setdefault(child_name, set()).add(parent_name)
                    
        project_info = data.get("project", {})
        frameworks = project_info.get("frameworks", {})
        for _fw_name, fw_info in frameworks.items():
            deps = fw_info.get("dependencies", {})
            for child_name in deps.keys():
                parents.setdefault(child_name, set()).add("root")
                
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        parents_clean = {k: list(v) for k, v in parents.items()}
        return resolved_clean, parents_clean
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading project.assets.json: {e}{COLOR_RESET}")
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
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            latest_same_major, latest_absolute = find_latest_same_major(clean_ver, valid_versions)
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            update_type = determine_update_type(clean_ver, latest_same_major, latest_absolute)
                
            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in ("major", "minor-major", "patch-major"):
                repo_url = resolve_nuget_repo(name, latest_absolute)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "releases_url": releases_url
            })
            
    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": error_msg
            })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": str(e)
            })
            
    return results

def check_all_nuget_targets(targets, max_workers):
    """Executes NuGet checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(targets, check_nuget_package, f"{COLOR_GRAY}[Progress: NuGet check]", max_workers)

def run_nuget_checker(args):
    """Main orchestrator for NuGet checker."""
    manifests, assets_files = find_nuget_files(args.path)
    
    if not manifests and not assets_files:
        print(f"{COLOR_RED}{ICON_ERROR} No C# / VB.NET project files or project.assets.json found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    pkg_data = {}
    print(f"{COLOR_GRAY}{ICON_INFO} Reading C# / VB.NET project references...{COLOR_RESET}")
    for manifest in manifests:
        proj_dir = os.path.dirname(manifest)
        cpm_versions = find_and_parse_cpm_versions(proj_dir)
        proj_deps = parse_csproj_or_config(proj_dir, cpm_versions)
        pkg_data.update(proj_deps)
        
    lock_data = {}
    parents_data = {}
    if assets_files:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading project.assets.json files...{COLOR_RESET}")
        for assets_file in assets_files:
            proj_lock, proj_parents = parse_project_assets(assets_file)
            for k, v_list in proj_lock.items():
                lock_data.setdefault(k, set()).update(v_list)
            for k, p_list in proj_parents.items():
                parents_data.setdefault(k, set()).update(p_list)
                
        lock_data = {k: list(v) for k, v in lock_data.items()}
        parents_data = {k: list(v) for k, v in parents_data.items()}
        
    targets = build_check_targets(
        {"all_direct": pkg_data} if pkg_data else None,
        lock_data,
        args.all
    )
    
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_nuget_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["nuget"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
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
        r["required_by"] = sorted(list(direct_parents - {r["name"]}))
            
    elapsed = time.time() - start_time
    
    return results, {"dependencies": pkg_data, "devDependencies": {}, "all_direct": pkg_data}, elapsed

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
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing composer.json: {e}{COLOR_RESET}")
        
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
                for child_name in reqs.keys():
                    if "/" in child_name:
                        parents.setdefault(child_name, set()).add(name)
                        
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading composer.lock: {e}{COLOR_RESET}")
        
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
            if not any(x in v_lower for x in ("-", "dev", "alpha", "beta", "rc", "patch")):
                if re.match(r'^\d+\.\d+(?:\.\d+)?(?:\.\d+)?$', v):
                    stable_versions.append(v)
                    
        valid_versions = stable_versions if stable_versions else versions_list
        
        for ver_str in versions_to_check:
            clean_ver = ver_str.lstrip("v") if ver_str else "0.0.0"
            if not clean_ver or clean_ver == "0.0.0":
                clean_ver = "0.0.0"
                
            latest_same_major, latest_absolute = find_latest_same_major(clean_ver, valid_versions)
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            update_type = determine_update_type(clean_ver, latest_same_major, latest_absolute)
                
            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in ("major", "minor-major", "patch-major"):
                raw_url = None
                for item in pkg_data:
                    v_str = item.get("version", "").lstrip("v")
                    if v_str == latest_absolute:
                        raw_url = item.get("source", {}).get("url") or item.get("homepage")
                        break
                if not raw_url and pkg_data:
                    raw_url = pkg_data[0].get("source", {}).get("url") or pkg_data[0].get("homepage")
                repo_url = clean_repo_url(raw_url)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "releases_url": releases_url
            })
            
    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": error_msg
            })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": str(e)
            })
            
    return results

def check_all_composer_targets(targets, max_workers):
    """Executes Packagist checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(targets, check_composer_package, f"{COLOR_GRAY}[Progress: Composer check]", max_workers)

def run_composer_checker(args):
    """Main orchestrator for PHP / Composer checker."""
    manifest, lock_file = find_composer_files(args.path)
    
    if not manifest and not lock_file:
        print(f"{COLOR_RED}{ICON_ERROR} No composer.json or composer.lock found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    dependencies = {}
    devDependencies = {}
    if manifest:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading composer.json dependencies...{COLOR_RESET}")
        dependencies, devDependencies = parse_composer_json(manifest)
        
    lock_data = {}
    parents_data = {}
    if lock_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading composer.lock...{COLOR_RESET}")
        lock_data, parents_data = parse_composer_lock(lock_file)
        
    all_direct = {**dependencies, **devDependencies}
    targets = build_check_targets(
        {"dependencies": dependencies, "devDependencies": devDependencies, "all_direct": all_direct},
        lock_data,
        args.all
    )
    
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_composer_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["php"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
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
        r["required_by"] = sorted(list(direct_parents - {r["name"]}))
            
    elapsed = time.time() - start_time
    
    return results, {"dependencies": dependencies, "devDependencies": devDependencies, "all_direct": all_direct}, elapsed

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
                        module_pom = os.path.abspath(os.path.join(root_dir, module_path, "pom.xml"))
                        if _is_safe_path(base_dir, module_pom) and os.path.exists(module_pom):
                            poms.extend(find_all_maven_poms(module_pom, base_dir=base_dir, visited=visited))
    except Exception:
        pass
        
    seen = set()
    unique_poms = []
    for p in poms:
        if p not in seen:
            seen.add(p)
            unique_poms.append(p)
            
    return unique_poms

def parse_maven_pom_recursive(filepath, parent_dep_mgmt=None, seen_files=None, base_dir=None):
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
                rel_path = rel_path_elem.text.strip() if (rel_path_elem is not None and rel_path_elem.text) else "../pom.xml"
                parent_pom_path = os.path.abspath(os.path.join(os.path.dirname(abs_path), rel_path))
                if _is_safe_path(base_dir, parent_pom_path) and os.path.exists(parent_pom_path):
                    _p_deps, p_props, p_dep_mgmt = parse_maven_pom_recursive(parent_pom_path, parent_dep_mgmt, seen_files, base_dir=base_dir)
                    properties.update(p_props)
                    dep_mgmt.update(p_dep_mgmt)
                    
            # 2. Parse local properties
            props_elem = root.find(f"{prefix}properties")
            if props_elem is not None:
                for elem in props_elem:
                    tag_local = elem.tag.split("}")[-1]
                    properties[f"${{{tag_local}}}"] = (elem.text or "").strip()
                    
            properties["${project.version}"] = (root.findtext(f"{prefix}version") or "").strip()
            properties["${project.groupId}"] = (root.findtext(f"{prefix}groupId") or "").strip()
            
            if parent_elem is not None:
                if not properties["${project.version}"]:
                    properties["${project.version}"] = (parent_elem.findtext(f"{prefix}version") or "").strip()
                if not properties["${project.groupId}"]:
                    properties["${project.groupId}"] = (parent_elem.findtext(f"{prefix}groupId") or "").strip()
                    
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
                        
                        for prop_name, prop_val in properties.items():
                            group = group.replace(prop_name, prop_val)
                            artifact = artifact.replace(prop_name, prop_val)
                            
                        if group and artifact:
                            coord = f"{group}:{artifact}"
                            version = "*"
                            if v_elem is not None and v_elem.text:
                                version = v_elem.text.strip()
                                for prop_name, prop_val in properties.items():
                                    version = version.replace(prop_name, prop_val)
                            elif coord in dep_mgmt:
                                version = dep_mgmt[coord]
                                
                            dependencies[coord] = version
                            
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing pom.xml: {e}{COLOR_RESET}")
        
    return dependencies, properties, dep_mgmt

def parse_maven_pom(filepath, parent_dep_mgmt=None, base_dir=None):
    """Parses Maven pom.xml for direct dependencies, resolving parent properties and dependencyManagement."""
    deps, _, _ = parse_maven_pom_recursive(filepath, parent_dep_mgmt, base_dir=base_dir)
    return deps

def check_maven_package(target):
    """Queries Maven Central Repository for package metadata."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]
    
    versions_to_check = installed_versions if installed_versions else [declared]
    results = []
    
    try:
        if ":" not in name:
            raise ValueError(f"Invalid Maven coordinate structure: {name}")
            
        group_id, artifact_id = name.split(":", 1)
        group_path = group_id.replace(".", "/")
        # Determine registry search order (prioritize Google Maven for Android/Google groups)
        use_google_maven = (
            group_id.startswith(("androidx.", "com.google.android.", "com.android.", "android.arch."))
            or "android" in group_id
        )
        
        xml_data = None
        registries = [URL_GOOGLE_MAVEN, URL_MAVEN_REGISTRY] if use_google_maven else [URL_MAVEN_REGISTRY, URL_GOOGLE_MAVEN]
        
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
                
        if xml_data is None:
            raise ValueError(f"Failed to fetch metadata from Maven or Google registries: {last_error or 'Not found'}")
            
        root = safe_et_fromstring(xml_data)
        
        versions_list = []
        versioning_elem = root.find("versioning")
        if versioning_elem is not None:
            versions_elem = versioning_elem.find("versions")
            if versions_elem is not None:
                for v in versions_elem.findall("version"):
                    if v.text:
                        versions_list.append(v.text.strip())
                        
        stable_versions = []
        prerelease_pattern = re.compile(
            r'[-.]?(alpha|beta|rc|cr|m|preview|dev|snapshot|milestone)\d*\b',
            re.IGNORECASE
        )
        for v in versions_list:
            v_lower = v.lower()
            is_prerelease = False
            if "snapshot" in v_lower:
                is_prerelease = True
            else:
                m = prerelease_pattern.search(v_lower)
                if m:
                    is_prerelease = True
            if not is_prerelease:
                stable_versions.append(v)
                
        valid_versions = stable_versions if stable_versions else versions_list
        
        for ver_str in versions_to_check:
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            latest_same_major, latest_absolute = find_latest_same_major(clean_ver, valid_versions)
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            update_type = determine_update_type(clean_ver, latest_same_major, latest_absolute)
                
            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in ("major", "minor-major", "patch-major"):
                repo_url = resolve_maven_repo(successful_registry, group_path, artifact_id, latest_absolute)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "releases_url": releases_url
            })
            
    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": error_msg
            })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": str(e)
            })
            
    return results

def check_all_maven_targets(targets, max_workers):
    """Executes Maven Repository checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(targets, check_maven_package, f"{COLOR_GRAY}[Progress: Maven check]", max_workers)

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
    all_poms = find_all_maven_poms(manifest, base_dir=manifest_dir)
    
    if len(all_poms) > 1:
        print(f"{COLOR_GRAY}{ICON_INFO} Multi-module project detected. Found {len(all_poms)} modules.{COLOR_RESET}")
        
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
                    
            properties["${project.version}"] = (root.findtext(f"{prefix}version") or "").strip()
            properties["${project.groupId}"] = (root.findtext(f"{prefix}groupId") or "").strip()
            
            root_dep_mgmt = parse_maven_dependency_management(root, prefix, properties)
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading root dependencyManagement: {e}{COLOR_RESET}")
        
    # 2. Parse all module poms and merge active dependencies
    pkg_data = {}
    print(f"{COLOR_GRAY}{ICON_INFO} Reading Maven pom.xml modules...{COLOR_RESET}")
    for pom in all_poms:
        pom_deps = parse_maven_pom(pom, root_dep_mgmt, base_dir=manifest_dir)
        pkg_data.update(pom_deps)
        
    targets = []
    for name, declared_ver in pkg_data.items():
        targets.append({
            "name": name,
            "declared": declared_ver,
            "installed": [declared_ver] if declared_ver != "*" else []
        })
        
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_maven_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["maven"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []
            
    for r in results:
        r["required_by"] = []
        
    elapsed = time.time() - start_time
    
    return results, {"dependencies": pkg_data, "devDependencies": {}, "all_direct": pkg_data}, elapsed

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

def parse_go_mod(filepath):
    """Parses go.mod for direct and indirect dependencies."""
    dependencies = {}
    devDependencies = {}
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        in_require_block = False
        single_req_pat = re.compile(r'^\s*require\s+([^\s]+)\s+([^\s]+)(?:\s+//\s*(indirect))?\s*$')
        block_req_pat = re.compile(r'^\s*([^\s]+)\s+([^\s]+)(?:\s+//\s*(indirect))?\s*$')
        
        for line in lines:
            line_strip = line.strip()
            if not line_strip or line_strip.startswith("//"):
                continue
                
            if line_strip == "require (":
                in_require_block = True
                continue
            elif line_strip == ")":
                in_require_block = False
                continue
                
            if in_require_block:
                m = block_req_pat.match(line_strip)
                if m:
                    pkg = m.group(1)
                    ver = m.group(2)
                    is_indirect = m.group(3) == "indirect"
                    if is_indirect:
                        devDependencies[pkg] = ver
                    else:
                        dependencies[pkg] = ver
            else:
                m = single_req_pat.match(line_strip)
                if m:
                    pkg = m.group(1)
                    ver = m.group(2)
                    is_indirect = m.group(3) == "indirect"
                    if is_indirect:
                        devDependencies[pkg] = ver
                    else:
                        dependencies[pkg] = ver
                        
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing go.mod: {e}{COLOR_RESET}")
        
    return dependencies, devDependencies

def check_go_package(target):
    """Queries proxy.golang.org for Go module versions list."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]
    
    versions_to_check = installed_versions if installed_versions else [declared]
    results = []
    
    try:
        escaped_name = escape_go_module(name)
        url = f"{URL_GO_PROXY}{escaped_name}/@v/list"
        
        req = urllib.request.Request(url)
        with safe_urlopen(req, timeout=10) as response:
            resp_data = response.read().decode("utf-8")
            
        versions_list = [v.strip() for v in resp_data.split("\n") if v.strip()]
        
        stable_versions = []
        for v in versions_list:
            v_lower = v.lower()
            if not any(x in v_lower for x in ("-", "alpha", "beta", "rc", "dev")):
                clean_v = v.split("+")[0]
                stable_versions.append((v, clean_v))
                
        valid_versions = stable_versions if stable_versions else [(v, v.split("+")[0]) for v in versions_list]
        
        all_versions = [item[0] for item in valid_versions]
        
        for ver_str in versions_to_check:
            latest_same_major, latest_absolute = find_latest_same_major(ver_str, all_versions)
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            clean_ver = ver_str.lstrip("v").split("+")[0] if ver_str else "0.0.0"
            clean_latest_absolute = latest_absolute.lstrip("v").split("+")[0] if latest_absolute else "0.0.0"
            
            clean_latest_same = latest_same_major.lstrip("v").split("+")[0] if latest_same_major else "0.0.0"
            update_type = determine_update_type(clean_ver, clean_latest_same, clean_latest_absolute)
                
            repo_url = None
            compare_url = None
            releases_url = None
            if update_type in ("major", "minor-major", "patch-major"):
                repo_url = resolve_go_repo(name)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "releases_url": releases_url
            })
            
    except urllib.error.HTTPError as e:
        error_msg = "Not Found" if e.code == 404 else f"HTTP {e.code}"
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": error_msg
            })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": None,
                "status": "error",
                "deprecated": None,
                "error": str(e)
            })
            
    return results

def check_all_go_targets(targets, max_workers):
    """Executes Go modules checks concurrently and renders simple progress."""
    total = len(targets)
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    return _check_all_targets_unified(targets, check_go_package, f"{COLOR_GRAY}[Progress: Go check]", max_workers)

def run_go_checker(args):
    """Main orchestrator for Go Modules checker."""
    manifest = None
    if os.path.exists(args.path):
        if os.path.isdir(args.path):
            cand = os.path.join(args.path, "go.mod")
            if os.path.exists(cand):
                manifest = cand
        elif os.path.isfile(args.path) and args.path.endswith("go.mod"):
            manifest = args.path
            
    if not manifest:
        print(f"{COLOR_RED}{ICON_ERROR} No go.mod found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    print(f"{COLOR_GRAY}{ICON_INFO} Reading go.mod...{COLOR_RESET}")
    dependencies, devDependencies = parse_go_mod(manifest)
    
    all_direct = {**dependencies, **devDependencies}
    targets = []
    
    for name, declared_ver in all_direct.items():
        targets.append({
            "name": name,
            "declared": declared_ver,
            "installed": [declared_ver] if declared_ver else []
        })
        
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_go_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["go"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []
            
    direct_keys = set(dependencies.keys())
    for r in results:
        if r["name"] not in direct_keys:
            r["required_by"] = ["indirect"]
        else:
            r["required_by"] = []
        
    elapsed = time.time() - start_time
    
    return results, {"dependencies": dependencies, "devDependencies": devDependencies, "all_direct": all_direct}, elapsed

# ==============================================================================
# Rust (Cargo) Scanning Logic
# ==============================================================================

def find_rust_files(path):
    """Finds Cargo.toml and Cargo.lock files."""
    toml_path = None
    lock_path = None
    
    if os.path.exists(path):
        if os.path.isdir(path):
            t = os.path.join(path, "Cargo.toml")
            l = os.path.join(path, "Cargo.lock")
            if os.path.exists(t):
                toml_path = t
            if os.path.exists(l):
                lock_path = l
        elif os.path.isfile(path):
            if path.endswith("Cargo.toml"):
                toml_path = path
                l = os.path.join(os.path.dirname(path), "Cargo.lock")
                if os.path.exists(l):
                    lock_path = l
            elif path.endswith("Cargo.lock"):
                lock_path = path
                t = os.path.join(os.path.dirname(path), "Cargo.toml")
                if os.path.exists(t):
                    toml_path = t
                    
    return toml_path, lock_path

def parse_cargo_toml(filepath):
    """Parses Cargo.toml to extract direct dependency names."""
    dependencies = set()
    if not filepath or not os.path.exists(filepath):
        return dependencies
        
    current_section = None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                    
                # Detect sections, e.g. [dependencies] or [dependencies.tokio]
                m_sec = re.match(r'^\[([^\]]+)\]', line)
                if m_sec:
                    current_section = m_sec.group(1).strip()
                    continue
                    
                # Check dependency sections
                is_dep_section = (
                    current_section in ("dependencies", "dev-dependencies", "build-dependencies")
                    or (current_section and (
                        current_section.startswith("dependencies.")
                        or current_section.startswith("dev-dependencies.")
                        or current_section.startswith("build-dependencies.")
                    ))
                )
                
                if is_dep_section:
                    # Match name = "version" or name = { ... }
                    m_dep = re.match(r'^([a-zA-Z0-9_-]+)\s*=', line)
                    if m_dep:
                        dependencies.add(m_dep.group(1).strip())
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Cargo.toml: {e}{COLOR_RESET}")
        
    return dependencies

def parse_cargo_lock(filepath):
    """Parses Cargo.lock to extract all resolved package names, versions, and build parent tree."""
    resolved = {}
    parents = {}
    if not filepath or not os.path.exists(filepath):
        return resolved, parents
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        current_pkg = None
        current_version = None
        in_deps = False
        pkg_deps = []
        pkg_definitions = []
        
        for line in lines:
            line = line.strip()
            if line == "[[package]]":
                if current_pkg:
                    pkg_definitions.append({
                        "name": current_pkg,
                        "version": current_version,
                        "deps": pkg_deps
                    })
                current_pkg = None
                current_version = None
                pkg_deps = []
                in_deps = False
                continue
                
            if line.startswith("name ="):
                current_pkg = line.split("=")[1].replace('"', '').strip()
            elif line.startswith("version ="):
                current_version = line.split("=")[1].replace('"', '').strip()
            elif line.startswith("dependencies ="):
                if "[" in line and "]" in line:
                    dep_str = line.split("=")[1].strip(" []\"")
                    if dep_str:
                        pkg_deps = [d.strip().split()[0].replace('"', '') for d in dep_str.split(",")]
                elif "[" in line:
                    in_deps = True
            elif in_deps:
                if line == "]":
                    in_deps = False
                else:
                    dep_name = line.strip(",\" ")
                    if dep_name:
                        pkg_deps.append(dep_name.split()[0].replace('"', ''))
                        
        if current_pkg:
            pkg_definitions.append({
                "name": current_pkg,
                "version": current_version,
                "deps": pkg_deps
            })
            
        for pkg in pkg_definitions:
            name = pkg["name"]
            version = pkg["version"]
            if name and version:
                resolved.setdefault(name, set()).add(version)
            
            for dep in pkg["deps"]:
                if dep not in parents:
                    parents[dep] = set()
                parents[dep].add(name)
                
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Cargo.lock: {e}{COLOR_RESET}")
        
    resolved_clean = {k: list(v) for k, v in resolved.items()}
    parents_clean = {k: list(v) for k, v in parents.items()}
    return resolved_clean, parents_clean

def check_rust_package(target):
    """Queries crates.io API for crate metadata and checks target version."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]
    
    versions_to_check = installed_versions if installed_versions else [declared]
    results = []
    
    try:
        url = f"{URL_RUST_REGISTRY}{urllib.parse.quote(name)}"
        req = urllib.request.Request(url)
        # crates.io requires a User-Agent
        req.add_header("User-Agent", f"Kevlar-CheckDeps/{VERSION}")
        
        with safe_urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            
        crate_info = data.get("crate", {})
        latest_version = crate_info.get("max_stable_version") or crate_info.get("max_version")
        
        versions_meta = data.get("versions", [])
        yanked_versions = set()
        for v_meta in versions_meta:
            if v_meta.get("yanked"):
                yanked_versions.add(v_meta.get("num"))
                
        all_versions = [v.get("num") for v in versions_meta if v.get("num")]
        
        for ver_str in versions_to_check:
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            latest_same_major, latest_absolute = find_latest_same_major(clean_ver, all_versions)
            if latest_version:
                latest_absolute = latest_version
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            status = determine_update_type(clean_ver, latest_same_major, latest_absolute)
            
            is_deprecated = clean_ver in yanked_versions
            
            repo_url = None
            compare_url = None
            releases_url = None
            if status in ("major", "minor-major", "patch-major"):
                raw_url = crate_info.get("repository") or crate_info.get("homepage")
                repo_url = clean_repo_url(raw_url)
                if repo_url:
                    compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                    releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "releases_url": releases_url
            })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": ver_str,
                "installed": ver_str,
                "latest": "unknown",
                "status": "error",
                "deprecated": False,
                "error": str(e)
            })
            
    return results

def check_all_rust_targets(targets, max_workers):
    """Checks all Rust target crates in parallel."""
    return _check_all_targets_unified(targets, check_rust_package, "[Rust] Checking registry", max_workers)

def run_rust_checker(args):
    """Main orchestrator for Rust Cargo checker."""
    toml_path, lock_path = find_rust_files(args.path)
    if not toml_path and not lock_path:
        print(f"{COLOR_RED}{ICON_ERROR} No Cargo.toml or Cargo.lock found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    print(f"{COLOR_GRAY}{ICON_INFO} Reading Cargo files...{COLOR_RESET}")
    direct = parse_cargo_toml(toml_path)
    resolved, parents = parse_cargo_lock(lock_path)
    
    if not resolved and direct:
        resolved = {name: ["0.0.0"] for name in direct}
        
    pkg_data = {
        "all_direct": {name: name for name in direct},
        "dependencies": resolved
    }
    
    targets = []
    for name, versions in resolved.items():
        if not args.all and name not in direct:
            continue
        declared = versions[0] if versions else None
        targets.append({
            "name": name,
            "declared": declared,
            "installed": versions if versions != ["0.0.0"] else []
        })
        
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No Rust packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_rust_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["rust"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []
            
    # Resolve transitive dependency parents
    for r in results:
        direct_parents = find_direct_parents(r["name"], parents, direct)
        r["required_by"] = sorted(list(direct_parents - {r["name"]}))
            
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
                leading_spaces = len(line) - len(line.lstrip(' '))
                
                # Try to match gem version pattern: "    name (version)"
                m_spec = re.match(r'^\s*([a-zA-Z0-9_-]+)\s*\(([^)]+)\)', line)
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
                if spec_indent is not None and leading_spaces > spec_indent and current_parent:
                    m_dep = re.match(r'^\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]+)\))?', line)
                    if m_dep:
                        child = m_dep.group(1)
                        if child not in parents:
                            parents[child] = set()
                        parents[child].add(current_parent)
                        
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Gemfile.lock: {e}{COLOR_RESET}")
        
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
            url_versions = f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(name)}.json"
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
        except Exception:
            # Fallback to single latest version endpoint
            url_fallback = f"{URL_RUBY_REGISTRY}{urllib.parse.quote(name)}.json"
            req_fb = urllib.request.Request(url_fallback)
            with safe_urlopen(req_fb, timeout=10) as response:
                data_fb = json.loads(response.read().decode("utf-8"))
            latest_version = data_fb.get("version")
            valid_versions = [latest_version] if latest_version else []
            
        for ver_str in versions_to_check:
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            latest_same_major, latest_absolute = find_latest_same_major(clean_ver, valid_versions)
            if not latest_same_major:
                latest_same_major = latest_absolute
                
            status = determine_update_type(clean_ver, latest_same_major, latest_absolute)
            
            repo_url = None
            compare_url = None
            releases_url = None
            if status in ("major", "minor-major", "patch-major"):
                try:
                    url_gem = f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json"
                    req_g = urllib.request.Request(url_gem)
                    with safe_urlopen(req_g, timeout=5) as response:
                        data_g = json.loads(response.read().decode("utf-8"))
                    raw_url = data_g.get("source_code_uri") or data_g.get("homepage_uri")
                    repo_url = clean_repo_url(raw_url)
                    if repo_url:
                        compare_url = get_compare_url(repo_url, clean_ver, latest_absolute)
                        releases_url = f"{repo_url}/releases" if is_github_url(repo_url) else repo_url
                except Exception:
                    pass
                    
            display_latest = format_latest_versions(latest_same_major, latest_absolute)
            results.append({
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
                "releases_url": releases_url
            })
    except Exception as e:
        for ver_str in versions_to_check:
            results.append({
                "name": name,
                "declared": ver_str,
                "installed": ver_str,
                "latest": "unknown",
                "status": "error",
                "deprecated": False,
                "error": str(e)
            })
            
    return results

def check_all_ruby_targets(targets, max_workers):
    """Checks all Ruby target gems in parallel."""
    return _check_all_targets_unified(targets, check_ruby_package, "[Ruby] Checking registry", max_workers)

def run_ruby_checker(args):
    """Main orchestrator for Ruby Bundler checker."""
    gemfile_path, lock_path = find_ruby_files(args.path)
    if not gemfile_path and not lock_path:
        print(f"{COLOR_RED}{ICON_ERROR} No Gemfile or Gemfile.lock found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    print(f"{COLOR_GRAY}{ICON_INFO} Reading Gemfile files...{COLOR_RESET}")
    direct = parse_gemfile(gemfile_path)
    resolved, parents = parse_gemfile_lock(lock_path)
    
    if not resolved and direct:
        resolved = {name: "0.0.0" for name in direct}
        
    pkg_data = {
        "all_direct": {name: name for name in direct},
        "dependencies": resolved
    }
    
    targets = []
    for name, version in resolved.items():
        if not args.all and name not in direct:
            continue
        targets.append({
            "name": name,
            "declared": version,
            "installed": [version] if version != "0.0.0" else []
        })
        
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No Ruby packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_ruby_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["ruby"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []
            
    # Resolve transitive dependency parents
    for r in results:
        direct_parents = find_direct_parents(r["name"], parents, direct)
        r["required_by"] = sorted(list(direct_parents - {r["name"]}))
            
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
                except Exception:
                    pass
            gl = os.path.join(path, "gradle.lockfile")
            if os.path.exists(gl):
                lock_files.append(gl)
        elif os.path.isfile(path):
            if path.endswith(".gradle") or path.endswith(".gradle.kts"):
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
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        versions = {}
        in_versions = False
        in_libraries = False
        
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
                
            if stripped.startswith("[versions]"):
                in_versions = True
                in_libraries = False
                continue
            elif stripped.startswith("[libraries]"):
                in_libraries = True
                in_versions = False
                continue
            elif stripped.startswith("["):
                in_versions = False
                in_libraries = False
                continue
                
            if in_versions:
                if "=" in stripped:
                    parts = stripped.split("=", 1)
                    var_name = parts[0].strip().strip('"').strip("'")
                    var_val = parts[1].strip().strip('"').strip("'")
                    versions[var_name] = var_val
            elif in_libraries:
                if "=" in stripped:
                    parts = stripped.split("=", 1)
                    _alias = parts[0].strip().strip('"').strip("'")
                    val = parts[1].strip()
                    
                    # Case 1: Simple string "group:name:version"
                    if val.startswith('"') or val.startswith("'"):
                        val_str = val.strip('"').strip("'")
                        m = val_str.split(":")
                        if len(m) >= 3:
                            group = m[0].strip()
                            name = m[1].strip()
                            ver = m[2].strip()
                            dependencies[f"{group}:{name}"] = ver
                    # Case 2: Inline table { ... }
                    elif val.startswith("{") and val.endswith("}"):
                        group = ""
                        name = ""
                        ver = ""
                        
                        module_match = re.search(r'module\s*=\s*["\']([^"\']+)["\']', val)
                        group_match = re.search(r'group\s*=\s*["\']([^"\']+)["\']', val)
                        name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', val)
                        version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', val)
                        ref_match = re.search(r'version\.ref\s*=\s*["\']([^"\']+)["\']', val)
                        
                        if module_match:
                            mod = module_match.group(1).split(":")
                            if len(mod) >= 2:
                                group = mod[0].strip()
                                name = mod[1].strip()
                        else:
                            if group_match:
                                group = group_match.group(1).strip()
                            if name_match:
                                name = name_match.group(1).strip()
                                
                        if version_match:
                            ver = version_match.group(1).strip()
                        elif ref_match:
                            ref = ref_match.group(1).strip()
                            ver = versions.get(ref, "*")
                            
                        if group and name:
                            dependencies[f"{group}:{name}"] = ver if ver else "*"
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading libs.versions.toml: {e}{COLOR_RESET}")
        
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
        p1 = re.compile(
            r'(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile|compileOnly)\s*\(?\s*[\'"]([^\'":]+):([^\'":]+):([^\'":]+)[\'"]'
        )
        for m in p1.finditer(content):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            version = m.group(3).strip()
            dependencies[f"{group}:{artifact}"] = version
            
        # Pattern 2: group: "...", name: "...", version: "..."
        p2 = re.compile(
            r'group\s*:\s*[\'"]([^\'"]+)[\'"]\s*,\s*name\s*:\s*[\'"]([^\'"]+)[\'"]\s*,\s*version\s*:\s*[\'"]([^\'"]+)[\'"]'
        )
        for m in p2.finditer(content):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            version = m.group(3).strip()
            dependencies[f"{group}:{artifact}"] = version
            
        # Pattern 3: group = "...", name = "...", version = "..."
        p3 = re.compile(
            r'group\s*=\s*[\'"]([^\'"]+)[\'"]\s*,\s*name\s*=\s*[\'"]([^\'"]+)[\'"]\s*,\s*version\s*=\s*[\'"]([^\'"]+)[\'"]'
        )
        for m in p3.finditer(content):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            version = m.group(3).strip()
            dependencies[f"{group}:{artifact}"] = version
            
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Gradle build file: {e}{COLOR_RESET}")
        
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
                m = re.match(r'^([^:]+):([^:]+):([^=]+)=', line)
                if m:
                    group = m.group(1).strip()
                    artifact = m.group(2).strip()
                    version = m.group(3).strip()
                    resolved[f"{group}:{artifact}"] = version
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing Gradle lockfile: {e}{COLOR_RESET}")
        
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
        print(f"{COLOR_RED}{ICON_ERROR} No build.gradle, build.gradle.kts, lockfiles or gradle/libs.versions.toml found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    print(f"{COLOR_GRAY}{ICON_INFO} Reading Gradle files...{COLOR_RESET}")
    
    direct = {}
    if catalog_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading Gradle Version Catalog (libs.versions.toml)...{COLOR_RESET}")
        direct.update(parse_libs_versions_toml(catalog_file))
        
    for f in build_files:
        direct.update(parse_gradle_build(f))
        
    resolved = {}
    for lf in lock_files:
        resolved.update(parse_gradle_lockfile(lf))
        
    if not resolved:
        resolved = direct
        
    pkg_data = {
        "all_direct": {name: name for name in direct},
        "dependencies": resolved
    }
    
    targets = []
    for name, version in resolved.items():
        if not args.all and name not in direct:
            continue
        targets.append({
            "name": name,
            "declared": version,
            "installed": [version] if version != "0.0.0" else []
        })
        
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No Gradle packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    # Reuses Maven Central checking logic
    results = check_all_maven_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["gradle"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
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
        if str(declared).strip().lower() in ("n/a", "unknown", ""):
            continue
        if str(installed).strip().lower() in ("n/a", "unknown", ""):
            continue
            
        decl_str = str(declared).strip()
        inst_str = str(installed).strip()
        
        # Skip checking if declared constraint is a git URL or local path
        if (decl_str.startswith(("git+", "git:", "http:", "https:", "ssh:", "file:")) 
            or "github:" in decl_str.lower() 
            or decl_str.startswith((".", "/"))):
            continue
            
        # Ensure we can extract a valid semantic version from installed version
        if parse_semver(inst_str) == (0, 0, 0, 0, 0, ''):
            continue
            
        try:
            satisfied = check_semver_satisfies(inst_str, decl_str)
        except Exception:
            satisfied = True
            
        if not satisfied:
            r["status"] = "error"
            r["error"] = f"Configuration Drift: Installed version '{inst_str}' violates declared constraint '{decl_str}'"

# ==============================================================================
# Output Formatting and Reporting
# ==============================================================================


class TerminalTextFormatter:
    """Utility class for terminal visual text formatting and character width calculations."""

    @staticmethod
    def get_char_width(char):
        """Returns visual terminal width of a character."""
        if char in ("🚫", "🛡️", "🛡"):
            return 2
        w = unicodedata.east_asian_width(char)
        if w in ('W', 'F'):
            return 2
        if ord(char) > 0xffff:
            return 2
        return 1

    @staticmethod
    def visual_len(s):
        """Calculates visual terminal length of a string, ignoring ANSI codes."""
        clean_s = re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', s)
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
        else: # center
            left = diff // 2
            right = diff - left
            return (" " * left) + text + (" " * right)

def print_results_table(results, pkg_data, show_all, vuls_enabled=False):
    """Draws a beautiful styled console report table with precise alignment."""
    filtered_results = []
    for r in results:
        is_issue = (
            r["status"] in ("major", "minor", "patch") 
            or r["deprecated"] 
            or r["status"] == "error"
            or (vuls_enabled and r.get("vulnerabilities"))
            or r.get("missing_checksum")
            or r.get("weak_checksum")
            or r.get("mismatch_checksum")
        )
        if show_all or is_issue:
            filtered_results.append(r)
            
    if not filtered_results:
        print(f"\n{COLOR_GREEN}{ICON_OK} All dependencies are up-to-date and secure!{COLOR_RESET}\n")
        return
        
    col_name = "Package"
    col_type = "Type"
    col_dec = "Declared"
    col_inst = "Installed"
    col_latest = "Latest"
    col_status = "Status"
    col_vuls = "Vuls"
    
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
        dep_type = "Transitive"
        if r.get("is_engine", False):
            dep_type = "Engine"
        elif pkg_data:
            if r["name"] in pkg_data.get("dependencies", {}):
                dep_type = "Direct"
            elif r["name"] in pkg_data.get("devDependencies", {}):
                dep_type = "Dev"
        if dep_type == "Transitive" and r.get("required_by") and not r.get("is_engine", False):
            dep_type = "Transitive"
                
        status_str = r["status"]
        color = COLOR_RESET
        icon = ""
        
        if status_str == "up-to-date":
            color = COLOR_GREEN
            status_display = "Up-to-date"
            icon = ICON_OK
        elif status_str == "patch":
            color = COLOR_CYAN
            status_display = "Patch Update"
            icon = ICON_WARN
        elif status_str == "minor":
            color = COLOR_YELLOW
            status_display = "Minor Update"
            icon = ICON_WARN
        elif status_str == "major":
            color = COLOR_RED
            status_display = "Major Update"
            icon = ICON_ERROR
        elif status_str == "error":
            color = COLOR_GRAY
            status_display = "Error"
            icon = ICON_ERROR
        elif status_str == "local":
            color = COLOR_CYAN
            status_display = "Verify Local"
            icon = "🔍"
        elif status_str == "minor-major":
            color = COLOR_RED
            status_display = "Minor/Major"
            icon = ICON_ERROR
        elif status_str == "patch-major":
            color = COLOR_RED
            status_display = "Patch/Major"
            icon = ICON_ERROR
            
        if r["deprecated"]:
            status_display = "Deprecated"
            color = COLOR_MAGENTA
            icon = ICON_DEPRECATED
            
        styled_status = f"{color}{icon} {status_display}{COLOR_RESET}"
        
        name_cell = TerminalTextFormatter.pad_string(f" {r['name']}", w_name, align="left")
        type_cell = TerminalTextFormatter.pad_string(dep_type, w_type, align="center")
        dec_cell = TerminalTextFormatter.pad_string(r['declared'] or 'N/A', w_dec, align="center")
        inst_cell = TerminalTextFormatter.pad_string(r['installed'] or 'N/A', w_inst, align="center")
        latest_cell = TerminalTextFormatter.pad_string(r['latest'] or 'N/A', w_latest, align="center")
        status_cell = TerminalTextFormatter.pad_string(styled_status, w_status, align="center")
        
        if vuls_enabled:
            vuls_list = r.get("vulnerabilities", [])
            vuls_count = len(vuls_list)
            if vuls_count > 0:
                styled_vuls = f"{COLOR_RED}{COLOR_BOLD}{vuls_count}{COLOR_RESET}"
            else:
                styled_vuls = f"{COLOR_GREEN}{ICON_OK}{COLOR_RESET}" if ICON_OK == "✔" else f"{COLOR_GREEN}0{COLOR_RESET}"
            vuls_cell = TerminalTextFormatter.pad_string(styled_vuls, w_vuls, align="center")
            
            print(f"{t['vertical']}{name_cell}{t['vertical']}{type_cell}{t['vertical']}{dec_cell}{t['vertical']}{inst_cell}{t['vertical']}{latest_cell}{t['vertical']}{status_cell}{t['vertical']}{vuls_cell}{t['vertical']}")
        else:
            print(f"{t['vertical']}{name_cell}{t['vertical']}{type_cell}{t['vertical']}{dec_cell}{t['vertical']}{inst_cell}{t['vertical']}{latest_cell}{t['vertical']}{status_cell}{t['vertical']}")
        
    print(border_bot)
    
    # Print warnings & errors section
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
            
    # Print Major Update Diffs section
    major_diffs_to_print = []
    for r in filtered_results:
        if r["status"] in ("major", "minor-major", "patch-major") and r.get("compare_url"):
            major_diffs_to_print.append(f"  {COLOR_BOLD}{r['name']}{COLOR_RESET}: {COLOR_CYAN}{r['compare_url']}{COLOR_RESET}")
            
    if major_diffs_to_print:
        print(f"\n{COLOR_BOLD}Major Update Diffs:{COLOR_RESET}")
        for diff_note in major_diffs_to_print:
            print(diff_note)
            
    # Print security vulnerabilities details section
    if vuls_enabled:
        vuls_to_print = []
        suppressed_to_print = []
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "unknown": 0
        }
        for r in filtered_results:
            vuls_list = r.get("vulnerabilities", [])
            if vuls_list:
                sorted_v = sorted(vuls_list, key=lambda v: severity_order.get(get_severity_level(v), 0), reverse=True)
                vuls_to_print.append((r["name"], r["installed"] if r["installed"] else r["declared"], sorted_v, r.get("required_by", [])))
            suppressed_list = r.get("suppressed_vulnerabilities", [])
            if suppressed_list:
                suppressed_to_print.append((r["name"], r["installed"] if r["installed"] else r["declared"], suppressed_list, r.get("required_by", [])))
                
        if vuls_to_print:
            # Sort package groups by their maximum vulnerability severity descending, and alphabetically by package name ascending
            vuls_to_print.sort(
                key=lambda x: (
                    -max(severity_order.get(get_severity_level(v), 0) for v in x[2]) if x[2] else 1,
                    x[0].lower()
                )
            )
            print(f"\n{COLOR_BOLD}{COLOR_RED}{ICON_SHIELD} Security Vulnerabilities Details:{COLOR_RESET}")
            for name, ver, v_list, required_by in vuls_to_print:
                parent_suffix = f" (via {', '.join(required_by)})" if required_by else ""
                print(f"  {COLOR_BOLD}{name}@{ver}{parent_suffix}{COLOR_RESET} ({len(v_list)} vulnerabilities found):")
                for vuln in v_list:
                    vid = vuln["id"]
                    severity = vuln["severity"]
                    summary = vuln["summary"]
                    
                    # Highlight severity
                    sev_color = COLOR_GRAY
                    level = get_severity_level(vuln)
                    if level == "critical" or level == "high":
                        sev_color = COLOR_RED
                    elif level == "medium":
                        sev_color = COLOR_YELLOW
                    elif level == "low":
                        sev_color = COLOR_CYAN
                        
                    print(f"    - {COLOR_BOLD}{vid}{COLOR_RESET} [{sev_color}{severity}{COLOR_RESET}]: {summary}")
                    
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

def print_summary(results, elapsed_time, vuls_enabled=False):
    """Prints checks run count and categorization breakdown."""
    total = len(results)
    up_to_date = sum(1 for r in results if r["status"] in ("up-to-date", "local"))
    patch = sum(1 for r in results if r["status"] in ("patch", "patch-major"))
    minor = sum(1 for r in results if r["status"] in ("minor", "minor-major"))
    major = sum(1 for r in results if r["status"] in ("major", "minor-major", "patch-major"))
    deprecated = sum(1 for r in results if r["deprecated"])
    errors = sum(1 for r in results if r["status"] == "error")
    
    outdated_total = sum(1 for r in results if r["status"] in ("patch", "minor", "major", "minor-major", "patch-major"))
    
    print(f"\n{COLOR_BOLD}{COLOR_CYAN}Summary Report:{COLOR_RESET}")
    print(f"  Checked:     {total} packages in {elapsed_time:.2f}s")
    print(f"  Up-to-date:  {COLOR_GREEN}{up_to_date}{COLOR_RESET}")
    print(f"  Outdated:    {COLOR_YELLOW}{outdated_total}{COLOR_RESET} (Patch: {COLOR_CYAN}{patch}{COLOR_RESET}, Minor: {COLOR_YELLOW}{minor}{COLOR_RESET}, Major: {COLOR_RED}{major}{COLOR_RESET})")
    if deprecated > 0:
        print(f"  Deprecated:  {COLOR_MAGENTA}{deprecated}{COLOR_RESET}")
    if errors > 0:
        print(f"  Errors:      {COLOR_RED}{errors}{COLOR_RESET}")
        
    if vuls_enabled:
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
        vuln_pkg_count = sum(1 for r in results if r.get("vulnerabilities"))
        suppressed_vulns = sum(len(r.get("suppressed_vulnerabilities", [])) for r in results)
        if total_vulns > 0:
            print(f"  Sec Vulnerabilities: {COLOR_RED}{COLOR_BOLD}{total_vulns}{COLOR_RESET} (in {vuln_pkg_count} packages)")
        else:
            print(f"  Sec Vulnerabilities: {COLOR_GREEN}0{COLOR_RESET}")
        if suppressed_vulns > 0:
            print(f"  Suppressed Alerts:   {COLOR_GRAY}{suppressed_vulns}{COLOR_RESET}")
    print()

def export_json_report(results, filepath):
    """Exports results as raw JSON data."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"{COLOR_GREEN}{ICON_OK} JSON report successfully exported to {filepath}{COLOR_RESET}")
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
                "informationUri": "https://github.com/brunoevn/kevlar-checkdeps",
                "rules": []
            }
        },
        "results": []
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
                                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                                        manifest_lines_cache[path] = f.readlines()
                                except Exception:
                                    manifest_lines_cache[path] = []
                            else:
                                manifest_lines_cache[path] = []
                        
                        lines = manifest_lines_cache[path]
                        for idx, line in enumerate(lines):
                            if match_line_for_dependency(line, name, tech):
                                manifest_path = path
                                line_number = idx + 1
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
                        "artifactLocation": {
                            "uri": uri
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": 1
                        }
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
            if severity in ("critical", "high"):
                sarif_level = "error"
            elif severity == "medium":
                sarif_level = "warning"
            else:
                sarif_level = "note"
                
            msg_text = f"Security Vulnerability: package '{name}' (version {installed}) has vulnerability {vuln_id}. Summary: {summary}"
            if details:
                msg_text += f"\nDetails: {details}"
                
            sarif_results.append({
                "ruleId": vuln_id,
                "message": {
                    "text": msg_text
                },
                "level": sarif_level,
                "locations": make_locations(rel_uri, line_number),
                "properties": {
                    "packageName": name,
                    "installedVersion": installed,
                    "declaredConstraint": declared,
                    "technology": tech,
                    "vulnerabilityDetails": vuln
                }
            })
            
            # Track in tool rules
            if vuln_id not in rules_map:
                rules_map[vuln_id] = {
                    "id": vuln_id,
                    "shortDescription": {
                        "text": f"Vulnerability {vuln_id} in {name}"
                    }
                }
                
        # 2. Map Configuration Drift (status == "error" and error starts with "Configuration Drift")
        is_config_drift = False
        if status == "error" and error_msg and error_msg.startswith("Configuration Drift"):
            is_config_drift = True
            rule_id = "KEVLAR-CONFIG-DRIFT"
            sarif_results.append({
                "ruleId": rule_id,
                "message": {
                    "text": error_msg
                },
                "level": "error",
                "locations": make_locations(rel_uri, line_number),
                "properties": {
                    "packageName": name,
                    "installedVersion": installed,
                    "declaredConstraint": declared,
                    "technology": tech
                }
            })
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": "Installed version of dependency violates declared constraint (Configuration Drift)"
                    }
                }
                
        # 3. Map Outdated Dependency (status in ("major", "minor", "patch") and not is_config_drift)
        if status in ("major", "minor", "patch") and not is_config_drift:
            rule_id = "KEVLAR-OUTDATED-DEPENDENCY"
            latest = r.get("latest") or "unknown"
            
            if status == "major":
                sarif_level = "error"
            elif status == "minor":
                sarif_level = "warning"
            else:
                sarif_level = "note"
                
            msg_text = f"Outdated dependency: package '{name}' (version {installed}) is behind latest version '{latest}' ({status} update available)."
            
            sarif_results.append({
                "ruleId": rule_id,
                "message": {
                    "text": msg_text
                },
                "level": sarif_level,
                "locations": make_locations(rel_uri, line_number),
                "properties": {
                    "packageName": name,
                    "installedVersion": installed,
                    "latestVersion": latest,
                    "declaredConstraint": declared,
                    "technology": tech,
                    "updateType": status
                }
            })
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": "Package version is outdated"
                    }
                }
                
        # 4. Map Deprecation
        if deprecated:
            rule_id = "KEVLAR-DEPRECATED-PACKAGE"
            dep_msg = str(deprecated)
            
            sarif_results.append({
                "ruleId": rule_id,
                "message": {
                    "text": f"Deprecated package '{name}': {dep_msg}"
                },
                "level": "warning",
                "locations": make_locations(rel_uri, line_number),
                "properties": {
                    "packageName": name,
                    "installedVersion": installed,
                    "technology": tech
                }
            })
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": "Package is deprecated"
                    }
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
            "runs": [run]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2)
        print(f"{COLOR_GREEN}{ICON_OK} SARIF report successfully exported to {filepath}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to export SARIF report: {e}{COLOR_RESET}")

def export_markdown_report(results, pkg_data, filepath, vuls_enabled=False):
    """Exports results as a clean Markdown document."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# Dependency Status Report\n")
            f.write("[GitHub Repository](https://github.com/brunoevn/kevlar-checkdeps)\n\n")
            f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Write summary
            total = len(results)
            up_to_date = sum(1 for r in results if r["status"] in ("up-to-date", "local"))
            patch = sum(1 for r in results if r["status"] in ("patch", "patch-major"))
            minor = sum(1 for r in results if r["status"] in ("minor", "minor-major"))
            major = sum(1 for r in results if r["status"] in ("major", "minor-major", "patch-major"))
            deprecated = sum(1 for r in results if r["deprecated"])
            errors = sum(1 for r in results if r["status"] == "error")
            outdated_total = sum(1 for r in results if r["status"] in ("patch", "minor", "major", "minor-major", "patch-major"))
            
            f.write("## Summary\n\n")
            f.write(f"- **Total Checked**: {total}\n")
            f.write(f"- **Up-to-date**: {up_to_date}\n")
            f.write(f"- **Outdated**: {outdated_total} (Patch: {patch}, Minor: {minor}, Major: {major})\n")
            if deprecated:
                f.write(f"- **Deprecated**: {deprecated}\n")
            if errors:
                f.write(f"- **Errors**: {errors}\n")
                
            if vuls_enabled:
                total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
                vuln_pkg_count = sum(1 for r in results if r.get("vulnerabilities"))
                suppressed_vulns = sum(len(r.get("suppressed_vulnerabilities", [])) for r in results)
                f.write(f"- **Security Vulnerabilities**: {total_vulns} found in {vuln_pkg_count} packages\n")
                if suppressed_vulns > 0:
                    f.write(f"- **Suppressed Alerts**: {suppressed_vulns}\n")
            f.write("\n")
            
            # Write table
            f.write("## Dependency Details\n\n")
            if vuls_enabled:
                f.write("| Package | Type | Declared | Installed | Latest | Status | Vuls | Note |\n")
                f.write("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
            else:
                f.write("| Package | Type | Declared | Installed | Latest | Status | Note |\n")
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
                        
                if dep_type == "Transitive" and r.get("required_by") and not r.get("is_engine", False):
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
                    notes_list.append("❌ **INTEGRITY MISMATCH!** Lockfile checksum does not match official registry checksum")
                
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
                    f.write(f"| `{r['name']}` | {dep_type} | `{r['declared'] or 'N/A'}` | `{r['installed'] or 'N/A'}` | `{r['latest'] or 'N/A'}` | {status_display} | {vuls_str} | {note} |\n")
                else:
                    f.write(f"| `{r['name']}` | {dep_type} | `{r['declared'] or 'N/A'}` | `{r['installed'] or 'N/A'}` | `{r['latest'] or 'N/A'}` | {status_display} | {note} |\n")
            
            # Write detailed security section
            if vuls_enabled:
                vuls_list_total = []
                severity_order = {
                    "critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                    "unknown": 0
                }
                for r in results:
                    v_list = r.get("vulnerabilities", [])
                    if v_list:
                        sorted_v = sorted(v_list, key=lambda v: severity_order.get(get_severity_level(v), 0), reverse=True)
                        vuls_list_total.append((r["name"], r["installed"], sorted_v, r.get("required_by", [])))
                        
                if vuls_list_total:
                    # Sort package groups by their maximum vulnerability severity descending, and alphabetically by package name ascending
                    vuls_list_total.sort(
                        key=lambda x: (
                            -max(severity_order.get(get_severity_level(v), 0) for v in x[2]) if x[2] else 1,
                            x[0].lower()
                        )
                    )
                    f.write("\n## Security Vulnerabilities Details\n\n")
                    for name, ver, v_list, required_by in vuls_list_total:
                        parent_suffix = f" (via {', '.join(required_by)})" if required_by else ""
                        f.write(f"### `{name}@{ver}`{parent_suffix} ({len(v_list)} vulnerabilities)\n\n")
                        for vuln in v_list:
                            f.write(f"- **{vuln['id']}** [{get_severity_level(vuln).upper()} - {vuln['severity']}]: {vuln['summary']}\n")
                            if vuln.get("details"):
                                details_escaped = vuln['details'].replace('\n', '\n> ')
                                f.write(f"  > {details_escaped}\n\n")
                            else:
                                f.write("\n")
                                
                # Write suppressed vulnerabilities if any exist
                suppressed_list_total = []
                for r in results:
                    s_list = r.get("suppressed_vulnerabilities", [])
                    if s_list:
                        suppressed_list_total.append((r["name"], r["installed"] if r["installed"] else r["declared"], s_list, r.get("required_by", [])))
                        
                if suppressed_list_total:
                    f.write("\n## Suppressed Vulnerabilities (Ignored)\n\n")
                    for name, ver, s_list, required_by in suppressed_list_total:
                        parent_suffix = f" (via {', '.join(required_by)})" if required_by else ""
                        f.write(f"### `{name}@{ver}`{parent_suffix} ({len(s_list)} suppressed)\n\n")
                        for vuln in s_list:
                            f.write(f"- **{vuln['id']}**: {vuln['summary']}\n")
                            f.write(f"  - **Reason**: {vuln.get('suppressed_reason', 'N/A')}\n")
                            f.write(f"  - **Justification**: {vuln.get('justification', 'N/A')}\n")
                            f.write(f"  - **Expires At**: {vuln.get('expires_at', 'N/A')}\n")
                            if vuln.get("approved_by"):
                                f.write(f"  - **Approved By**: {vuln['approved_by']}\n")
                            f.write("\n")
                                
        print(f"{COLOR_GREEN}{ICON_OK} Markdown report successfully exported to {filepath}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to export Markdown report: {e}{COLOR_RESET}")

def escape_html(text):
    """Safely escape HTML characters."""
    if text is None:
        return ""
    text_str = str(text)
    return (text_str.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                    .replace("'", "&#x27;"))

def get_upgraded_constraint(declared_ver, latest_ver):
    """Synthesize upgraded constraint preserving prefixes like ^, ~, ==, >=."""
    if not declared_ver or not latest_ver:
        return latest_ver
    
    # Extract prefix, e.g., ^, ~, >=, ==, ~>
    match = re.match(r'^([~^>=<!\s]+)\s*(.*)$', declared_ver.strip())
    if match:
        prefix = match.group(1)
        return prefix + latest_ver
    
    return latest_ver

def _match_npm_php(line_lower, pkg_lower):
    pattern = r'"' + re.escape(pkg_lower) + r'"\s*:'
    return re.search(pattern, line_lower) is not None

def _match_pip(line_lower, pkg_lower):
    pattern_req = r'^\s*' + re.escape(pkg_lower) + r'\s*(==|>=|<=|~=|!=|>|<|@|;|$)'
    pattern_toml = r'^\s*' + re.escape(pkg_lower) + r'\s*=\s*'
    pattern_setup = r'[\'"]' + re.escape(pkg_lower) + r'([>=<!~]+|[\'"]\s*,)'
    return (re.search(pattern_req, line_lower) is not None or 
            re.search(pattern_toml, line_lower) is not None or
            re.search(pattern_setup, line_lower) is not None)

def _match_nuget(line_lower, pkg_lower):
    pattern = r'(include|update)\s*=\s*[\'"]' + re.escape(pkg_lower) + r'[\'"]'
    return re.search(pattern, line_lower) is not None

def _match_maven(line_lower, pkg_lower):
    parts = pkg_lower.split(":")
    artifact = parts[-1]
    pattern = r'<artifactid>\s*' + re.escape(artifact) + r'\s*</artifactid>'
    return re.search(pattern, line_lower) is not None

def _match_go(line_lower, pkg_lower):
    pattern = re.escape(pkg_lower) + r'\s+v\d+'
    return re.search(pattern, line_lower) is not None

def _match_rust(line_lower, pkg_lower):
    pattern = r'^\s*' + re.escape(pkg_lower) + r'\s*=\s*'
    return re.search(pattern, line_lower) is not None

def _match_ruby(line_lower, pkg_lower):
    pattern = r'gem\s+[\'"]' + re.escape(pkg_lower) + r'[\'"]'
    return re.search(pattern, line_lower) is not None

def _match_gradle(line_lower, pkg_lower):
    parts = pkg_lower.split(":")
    if len(parts) > 1:
        group, name_part = parts[0], parts[1]
        pattern_build = re.escape(group) + r':' + re.escape(name_part)
        return re.search(pattern_build, line_lower) is not None
    else:
        pattern_toml = r'^\s*' + re.escape(pkg_lower) + r'\s*=\s*'
        pattern_name = r'name\s*=\s*[\'"]' + re.escape(pkg_lower) + r'[\'"]'
        return (re.search(pattern_toml, line_lower) is not None or 
                re.search(pattern_name, line_lower) is not None)

MATCH_STRATEGIES = {
    "npm": _match_npm_php,
    "php": _match_npm_php,
    "pip": _match_pip,
    "nuget": _match_nuget,
    "maven": _match_maven,
    "go": _match_go,
    "rust": _match_rust,
    "ruby": _match_ruby,
    "gradle": _match_gradle
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
        
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "bin", "obj", ".gradle", "venv", ".venv")]
        for file in files:
            for pattern in patterns:
                if pattern.startswith('.'):
                    if file.lower().endswith(pattern):
                        manifest_files.append(os.path.join(root, file))
                else:
                    if file == pattern:
                        manifest_files.append(os.path.join(root, file))
    return manifest_files

def generate_remediation_diff(manifest_path, line_index, declared_ver, latest_ver, tech):
    """Generates remediation diff showing current vs suggested change."""
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None
        
    idx = line_index - 1
    if idx < 0 or idx >= len(lines):
        return None
        
    line_idx_to_change = None
    target_text = None
    
    search_range = range(idx, min(idx + 4, len(lines)))
    
    if declared_ver:
        for i in search_range:
            if declared_ver in lines[i]:
                line_idx_to_change = i
                target_text = declared_ver
                break
                
    if line_idx_to_change is None and declared_ver:
        ver_digits = re.search(r'\d+\.\d+(?:\.\d+)?(?:\.\d+)?', declared_ver)
        if ver_digits:
            ver_clean = ver_digits.group(0)
            for i in search_range:
                if ver_clean in lines[i]:
                    line_idx_to_change = i
                    target_text = ver_clean
                    break
                    
    if line_idx_to_change is None:
        line_idx_to_change = idx
        ver_pattern = re.search(r'\d+\.\d+(?:\.\d+)?(?:\.\d+)?', lines[idx])
        if ver_pattern:
            target_text = ver_pattern.group(0)
        else:
            quotes_match = re.search(r'["\']([^"\']+)["\']', lines[idx])
            if quotes_match:
                quoted_vals = re.findall(r'["\']([^"\']+)["\']', lines[idx])
                if quoted_vals:
                    target_text = quoted_vals[-1]
                    
    if line_idx_to_change is None:
        return None
        
    match_prefix = ""
    match_version = target_text or ""
    if target_text:
        match_opt = re.match(r'^([~^>=<!\s]+)\s*(.*)$', target_text.strip())
        if match_opt:
            match_prefix = match_opt.group(1)
            match_version = match_opt.group(2)
            
    start_ctx = max(0, line_idx_to_change - 2)
    end_ctx = min(len(lines), line_idx_to_change + 3)
    
    current_block = []
    suggested_block = []
    
    for i in range(start_ctx, end_ctx):
        orig_line = lines[i].rstrip('\r\n')
        line_num = i + 1
        
        if i == line_idx_to_change:
            escaped_orig = escape_html(orig_line)
            if target_text and target_text in orig_line:
                escaped_target = escape_html(target_text)
                escaped_prefix = escape_html(match_prefix)
                escaped_version = escape_html(match_version)
                
                html_orig = escaped_orig.replace(
                    escaped_target, 
                    f'{escaped_prefix}<span class="diff-remove-chunk">{escaped_version}</span>'
                )
                new_line = orig_line.replace(target_text, match_prefix + latest_ver)
            else:
                html_orig = escaped_orig
                new_line = orig_line + f" -> {latest_ver}"
                
            escaped_new = escape_html(new_line)
            escaped_upgraded = escape_html(match_prefix + latest_ver)
            escaped_prefix = escape_html(match_prefix)
            escaped_latest = escape_html(latest_ver)
            
            if (match_prefix + latest_ver) in new_line:
                html_new = escaped_new.replace(
                    escaped_upgraded, 
                    f'{escaped_prefix}<span class="diff-add-chunk">{escaped_latest}</span>'
                )
            else:
                html_new = escaped_new
                
            current_block.append({
                "line_num": line_num,
                "html": html_orig,
                "is_changed": True
            })
            suggested_block.append({
                "line_num": line_num,
                "html": html_new,
                "is_changed": True
            })
        else:
            escaped_orig = escape_html(orig_line)
            current_block.append({
                "line_num": line_num,
                "html": escaped_orig,
                "is_changed": False
            })
            suggested_block.append({
                "line_num": line_num,
                "html": escaped_orig,
                "is_changed": False
            })
            
    return {
        "manifest_path": manifest_path,
        "line_number": line_idx_to_change + 1,
        "current_code": current_block,
        "suggested_code": suggested_block
    }

def populate_remediation_recommendations(results, default_project_path):
    """Calculates and attaches remediation info to each result if possible."""
    for r in results:
        r["remediation"] = None
        
        is_outdated = r.get("status") in ("major", "minor", "patch")
        has_vulns = bool(r.get("vulnerabilities"))
        is_depr = bool(r.get("deprecated"))
        
        if not (is_outdated or has_vulns or is_depr):
            continue
            
        latest_ver = r.get("latest_absolute") or r.get("latest")
        if not latest_ver:
            continue
            
        project_path = r.get("project_path") or default_project_path
        tech = r.get("technology")
        if not tech:
            continue
            
        name = r.get("name")
        declared = r.get("declared")
        
        # 1. Handle Special Case for engine
        if r.get("is_engine", False):
            package_json_path = os.path.join(project_path, "package.json")
            if os.path.exists(package_json_path):
                try:
                    with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for idx, line in enumerate(lines):
                        if f'"{name}"' in line or '"engines"' in line:
                            diff = generate_remediation_diff(package_json_path, idx + 1, declared, latest_ver, tech)
                            if diff:
                                r["remediation"] = diff
                                break
                except Exception:
                    pass
            continue
            
        # 2. General dependency matching
        manifest_files = find_manifest_files(project_path, tech)
        if not manifest_files:
            continue
            
        found = False
        for manifest_path in manifest_files:
            try:
                with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue
                
            for idx, line in enumerate(lines):
                if match_line_for_dependency(line, name, tech):
                    diff = generate_remediation_diff(manifest_path, idx + 1, declared, latest_ver, tech)
                    if diff:
                        r["remediation"] = diff
                        found = True
                        break
            if found:
                break

class HTMLReportTemplateProvider:
    @staticmethod
    def get_template():
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dependency Status & Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --card-hover: #1f2937;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --border-color: #374151;
            --primary: #38bdf8;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --info: #0ea5e9;
            --depr: #a855f7;
            --muted: #4b5563;
        }
        
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }
        
        .container {
            max-width: 1000px;
            width: 100%;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
        }
        
        h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 800;
            background: linear-gradient(135deg, #38bdf8 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .meta-info {
            font-size: 13px;
            color: var(--text-muted);
            text-align: right;
        }
        
        /* Grid Dashboard */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        .stat-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 15px;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .stat-card.primary-large {
            grid-column: span 2;
        }
        
        .stat-val {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .stat-lbl {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-card.primary .stat-val, .stat-card.primary-large .stat-val { color: var(--primary); }
        .stat-card.warning .stat-val { color: var(--warning); }
        .stat-card.error .stat-val { color: var(--error); }
        .stat-card.success .stat-val { color: var(--success); }
        .stat-card.muted .stat-val { color: var(--text-muted); }
        .stat-card.depr .stat-val { color: var(--depr); }
        
        /* Controls Toolbar */
        .controls-toolbar {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        /* Floating controls-toolbar styles on scroll */
        .controls-placeholder {
            display: block;
            margin-bottom: 25px;
        }
        
        @media (min-width: 768px) {
            .controls-toolbar.floating {
                position: fixed;
                top: 0;
                left: 50%;
                transform: translate(-50%, 0);
                width: 100%;
                max-width: 1000px;
                border-radius: 0 0 12px 12px;
                border-left: 1px solid var(--border-color);
                border-right: 1px solid var(--border-color);
                border-top: none;
                border-bottom: 1px solid var(--border-color);
                background-color: rgba(17, 24, 39, 0.95);
                backdrop-filter: blur(10px);
                z-index: 1000;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
                padding: 10px 20px;
                box-sizing: border-box;
                animation: desktopStickyIn 0.2s ease;
            }
        }
        
        /* Mobile Sticky fallback */
        @media (max-width: 767px) {
            .controls-toolbar.floating {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                border-radius: 0;
                border-left: 0;
                border-right: 0;
                border-top: 0;
                background-color: rgba(17, 24, 39, 0.95);
                backdrop-filter: blur(10px);
                z-index: 1000;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
                padding: 10px 15px;
                margin-bottom: 0;
                box-sizing: border-box;
                animation: mobileStickyIn 0.2s ease;
            }
            
            .controls-toolbar.floating .search-box {
                max-width: none;
                width: 100%;
            }
        }
        
        @keyframes desktopStickyIn {
            from {
                transform: translate(-50%, -100%);
            }
            to {
                transform: translate(-50%, 0);
            }
        }
        
        @keyframes mobileStickyIn {
            from {
                transform: translateY(-100%);
            }
            to {
                transform: translateY(0);
            }
        }
        
        .search-box {
            flex-grow: 1;
            position: relative;
            max-width: 400px;
            min-width: 200px;
        }
        
        .search-box input {
            width: 100%;
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-main);
            padding: 10px 35px 10px 12px;
            font-size: 14px;
            box-sizing: border-box;
            font-family: inherit;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: var(--primary);
        }
        
        #clearSearch {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 18px;
            cursor: pointer;
            padding: 0;
            line-height: 1;
            display: none;
            font-family: sans-serif;
        }
        
        #clearSearch:hover {
            color: var(--text-main);
        }
        
        .filter-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-group {
            position: relative;
            display: inline-block;
        }
        
        .chevron-inline {
            display: inline-block;
            font-size: 8px;
            margin-left: 6px;
            opacity: 0.7;
            transition: transform 0.2s ease;
        }
        
        .filter-btn.dropdown-open .chevron-inline {
            transform: rotate(180deg);
        }
        
        .filter-dropdown {
            position: absolute;
            top: calc(100% + 6px);
            left: 0;
            z-index: 100;
            background: rgba(17, 24, 39, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            min-width: 200px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -2px rgba(0, 0, 0, 0.5);
            display: none;
        }
        
        .dropdown-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            width: 100%;
        }
        
        .row-actions {
            display: inline-flex;
            align-items: center;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.15s ease;
            user-select: none;
        }
        
        .dropdown-row:hover .row-actions {
            opacity: 1;
            pointer-events: auto;
        }
        
        .action-btn {
            font-size: 10px;
            color: var(--primary);
            cursor: pointer;
            text-decoration: underline;
            font-weight: 500;
        }
        
        .action-btn:hover {
            color: var(--text-main);
        }
        
        .action-separator {
            font-size: 10px;
            color: var(--text-muted);
            margin: 0 3px;
        }
        
        @keyframes fadeInSlide {
            from {
                opacity: 0;
                transform: translateY(-8px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .filter-dropdown.show {
            display: flex;
            flex-direction: column;
            gap: 8px;
            animation: fadeInSlide 0.15s ease-out forwards;
        }
        
        .filter-dropdown label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            color: var(--text-main);
            cursor: pointer;
            user-select: none;
            transition: opacity 0.15s;
        }
        
        .filter-dropdown label:hover {
            opacity: 0.85;
        }
        
        .filter-dropdown input[type="checkbox"] {
            accent-color: var(--primary);
            cursor: pointer;
            width: 14px;
            height: 14px;
        }
        
        .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }
        .crit-dot { background-color: var(--error); }
        .high-dot { background-color: #f97316; }
        .med-dot { background-color: var(--warning); }
        .low-dot { background-color: var(--info); }
        .unkn-dot { background-color: var(--text-muted); }
        
        .filter-btn {
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            border-radius: 8px;
            padding: 8px 14px;
            font-size: 13px;
            cursor: pointer;
            font-family: inherit;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
        }
        
        .filter-btn:hover {
            background-color: var(--card-hover);
            color: var(--text-main);
        }
        
        .filter-btn.active {
            background: linear-gradient(135deg, #38bdf8 0%, #3b82f6 100%);
            border-color: var(--primary);
            color: white;
            font-weight: 600;
        }
        
        .filter-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
            pointer-events: none;
        }
        
        /* Packages list */
        .packages-list {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .package-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        .package-card:hover {
            border-color: rgba(59, 130, 246, 0.5);
            background-color: var(--card-hover);
            transform: translateY(-1px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
        
        .card-header {
            padding: 18px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            gap: 20px;
        }
        
        .card-header:hover {
            background-color: #161e2e;
        }
        
        .header-left {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .pkg-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .pkg-name {
            font-weight: 700;
            font-size: 16px;
        }
        
        .pkg-type-badge {
            font-size: 10px;
            background-color: #1e293b;
            color: var(--text-muted);
            padding: 2px 6px;
            border-radius: 4px;
            text-transform: uppercase;
        }
        
        .pkg-badges {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }
        
        .badge {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 6px;
            font-weight: 600;
        }
        
        .badge-success { background-color: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-warning { background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-error { background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-info { background-color: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.3); }
        .badge-depr { background-color: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
        .badge-danger { background-color: rgba(220, 38, 38, 0.25); color: #fca5a5; border: 1px solid rgba(220, 38, 38, 0.4); }
        .badge-muted { background-color: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }
        .badge-project { background-color: rgba(55, 65, 81, 0.4); color: #9ca3af; border: 1px solid rgba(75, 85, 99, 0.4); }
        
        .badge-vuln-stats {
            background-color: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #ef4444;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-weight: 700;
        }
        .vuln-severity-pills {
            display: inline-flex;
            gap: 4px;
            align-items: center;
        }
        .sev-pill {
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 5px;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
        }
        .sev-pill.sev-c { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
        .sev-pill.sev-h { background-color: rgba(245, 158, 11, 0.2); color: #fb923c; border: 1px solid rgba(245, 158, 11, 0.3); }
        .sev-pill.sev-m { background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
        .sev-pill.sev-l { background-color: rgba(156, 163, 175, 0.2); color: #d1d5db; border: 1px solid rgba(156, 163, 175, 0.3); }
        .sev-pill.sev-u { background-color: rgba(156, 163, 175, 0.15); color: #9ca3af; border: 1px solid rgba(156, 163, 175, 0.25); }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .pkg-versions {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 6px;
            font-family: 'Outfit', sans-serif;
        }
        
        .version-installed {
            font-size: 13px;
            color: var(--text-main);
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .version-installed .label {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: 400;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .version-chips {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 4px;
        }
        
        .v-chip {
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 6px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            transition: all 0.2s ease;
        }
        
        .v-chip-ok {
            background-color: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: #34d399;
        }
        
        .v-chip-safe {
            background-color: rgba(14, 165, 233, 0.1);
            border: 1px solid rgba(14, 165, 233, 0.2);
            color: #38bdf8;
        }
        
        .v-chip-major {
            background-color: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.2);
            color: #fbbf24;
        }
        
        .chevron {
            color: var(--text-muted);
            transition: transform 0.2s ease;
        }
        
        /* Details Expanded */
        .card-details {
            display: none;
            padding: 20px;
            background-color: #0d131f;
            border-top: 1px solid var(--border-color);
        }
        
        .required-by-section {
            font-size: 12px;
            color: var(--text-muted);
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            border-radius: 6px;
            margin-bottom: 15px;
            display: inline-block;
        }
        
        .error-section {
            color: #f87171;
            font-size: 13px;
            background-color: rgba(220, 38, 38, 0.1);
            border: 1px solid rgba(220, 38, 38, 0.3);
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 15px;
        }
        
        .section-title {
            font-size: 12px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 15px 0 10px 0;
        }
        
        /* Vulnerability item */
        .vuln-item {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--error);
            border-radius: 8px;
            padding: 12px 15px;
            margin-bottom: 12px;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }
        
        .vuln-id {
            font-weight: 700;
            font-size: 14px;
            color: #fca5a5;
        }
        
        .sev-badge {
            font-size: 10px;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 4px;
            text-transform: uppercase;
            display: inline-block;
        }
        
        .sev-critical { background-color: #ef4444; color: white; }
        .sev-high { background-color: #f97316; color: white; }
        .sev-medium { background-color: #eab308; color: black; }
        .sev-low { background-color: #0ea5e9; color: white; }
        .sev-unknown { background-color: #374151; color: white; }
        
        .vuln-summary {
            font-size: 13.5px;
            color: var(--text-main);
            margin-bottom: 8px;
            line-height: 1.4;
        }
        
        .vuln-details {
            font-family: monospace;
            font-size: 11px;
            background-color: var(--bg-color);
            padding: 10px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            overflow-x: auto;
            color: var(--text-muted);
            margin: 0;
            white-space: pre-wrap;
        }
        
        /* Suppressed item */
        .suppressed-item {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--muted);
            border-radius: 8px;
            padding: 12px 15px;
            margin-bottom: 12px;
        }
        
        .suppressed-item .vuln-id {
            color: var(--text-muted);
        }
        
        .suppressed-label {
            font-size: 10px;
            font-weight: 700;
            background-color: var(--muted);
            color: var(--text-main);
            padding: 2px 6px;
            border-radius: 4px;
            text-transform: uppercase;
        }
        
        .suppressed-reason {
            font-size: 12.5px;
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            border-radius: 6px;
            margin-top: 8px;
            color: #94a3b8;
        }
        
        /* Notes & Warnings inline section */
        .notes-warnings-section {
            background-color: rgba(245, 158, 11, 0.05);
            border: 1px solid rgba(245, 158, 11, 0.25);
            border-left: 4px solid var(--warning);
            border-radius: 8px;
            padding: 12px 15px;
            margin-bottom: 15px;
        }
        
        .section-title-inline {
            font-size: 11px;
            font-weight: 700;
            color: var(--warning);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .section-title-inline svg {
            stroke: var(--warning);
            fill: none;
        }
        
        .notes-warnings-body {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .note-warning-item {
            display: flex;
            align-items: flex-start;
            gap: 8px;
            font-size: 13px;
            line-height: 1.45;
            color: var(--text-main);
        }
        
        .note-warning-icon {
            flex-shrink: 0;
            font-size: 14px;
        }
        
        /* Changelog & Migration buttons */
        .changelog-btn {
            display: inline-flex;
            align-items: center;
            background-color: var(--border-color);
            color: var(--text-main);
            border: 1px solid var(--border-color);
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-decoration: none;
            margin-right: 8px;
            transition: all 0.2s ease;
        }
        .changelog-btn:hover {
            background-color: var(--primary);
            color: #0b0f19;
            border-color: var(--primary);
        }

        /* Modal backdrop */
        .modal-backdrop {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.7);
            z-index: 1000;
            backdrop-filter: blur(4px);
            transition: opacity 0.3s ease;
        }
        
        /* Modal box */
        .remediation-modal {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) scale(0.9);
            width: 90%;
            max-width: 950px;
            max-height: 85vh;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            z-index: 1001;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            overflow: hidden;
            transition: transform 0.3s ease, opacity 0.3s ease;
            opacity: 0;
        }
        
        .remediation-modal.active, .modal-backdrop.active {
            display: block;
            opacity: 1;
        }
        
        .remediation-modal.active {
            transform: translate(-50%, -50%) scale(1);
            display: flex;
            flex-direction: column;
        }
        
        .modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: #161e2e;
        }
        
        .modal-header h3 {
            margin: 0;
            font-size: 18px;
            font-weight: 700;
            color: var(--primary);
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 24px;
            cursor: pointer;
            line-height: 1;
            padding: 0;
        }
        
        .modal-close:hover {
            color: var(--text-main);
        }
        
        .modal-body {
            padding: 24px;
            overflow-y: auto;
            flex-grow: 1;
        }
        
        .modal-info-bar {
            display: flex;
            align-items: center;
            gap: 8px;
            background-color: #1e293b;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 10px 16px;
            font-family: monospace;
            font-size: 14px;
            margin-bottom: 20px;
            color: #e2e8f0;
        }
        
        .modal-diff-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        @media (max-width: 768px) {
            .modal-diff-container {
                grid-template-columns: 1fr;
            }
        }
        
        .diff-box {
            background-color: #0b0f19;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .diff-box-title {
            padding: 10px 16px;
            border-bottom: 1px solid var(--border-color);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background-color: #111827;
        }
        
        .diff-box-title.current {
            color: var(--error);
            border-left: 3px solid var(--error);
        }
        
        .diff-box-title.suggested {
            color: var(--success);
            border-left: 3px solid var(--success);
        }
        
        .diff-code {
            padding: 16px;
            margin: 0;
            font-family: 'Consolas', 'Courier New', Courier, monospace;
            font-size: 13px;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre;
        }
        
        .diff-line {
            display: flex;
            width: 100%;
        }
        
        .diff-line-num {
            width: 45px;
            text-align: right;
            padding-right: 12px;
            color: var(--text-muted);
            user-select: none;
            border-right: 1px solid var(--border-color);
            margin-right: 12px;
            font-size: 11px;
        }
        
        .diff-line-content {
            flex-grow: 1;
        }
        
        .diff-line.removed {
            background-color: rgba(239, 68, 68, 0.15);
        }
        
        .diff-line.added {
            background-color: rgba(16, 185, 129, 0.15);
        }
        
        .diff-remove-chunk {
            background-color: rgba(239, 68, 68, 0.4);
            text-decoration: line-through;
            padding: 1px 3px;
            border-radius: 3px;
        }
        
        .diff-add-chunk {
            background-color: rgba(16, 185, 129, 0.4);
            padding: 1px 3px;
            border-radius: 3px;
        }
        
        .btn-remediation {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            border: none;
            color: white;
            font-weight: 600;
            padding: 8px 16px;
            font-size: 12px;
            border-radius: 6px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: filter 0.2s ease;
        }
        
        .btn-remediation:hover {
            filter: brightness(1.1);
        }
        
        .btn-ai-prompt {
            background: linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%);
            border: none;
            color: white;
            font-weight: 600;
            padding: 8px 16px;
            font-size: 12px;
            border-radius: 6px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: filter 0.2s ease;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        .btn-ai-prompt:hover {
            filter: brightness(1.15);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1 style="display: flex; align-items: center; gap: 10px;">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="var(--primary)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; filter: drop-shadow(0 2px 8px rgba(56, 189, 248, 0.3));">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                    <span>Kevlar CheckDeps <span style="font-size: 13px; font-weight: normal; color: var(--text-muted); margin-left: 6px;">v${VERSION}</span></span>
                </h1>
                <div style="font-size: 14px; color: var(--text-muted); margin-top: 4px;">Dependency Status & Security Audit</div>
                <div style="font-size: 12px; margin-top: 6px;"><a href="https://github.com/brunoevn/kevlar-checkdeps" target="_blank" style="color: var(--primary); text-decoration: none;">https://github.com/brunoevn/kevlar-checkdeps</a></div>
            </div>
            <div class="meta-info">
                <div>Report Generated: <strong>${scan_date}</strong></div>
                <div>Ecosystem: <strong>${project_title}</strong></div>
                ${project_path_header_html}
            </div>
        </header>
        
        <div class="dashboard-grid">
            <!-- Stats -->
            <div class="stats-grid">
                <div class="stat-card primary-large">
                    <div class="stat-val">${total}</div>
                    <div class="stat-lbl">Checked</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-val">${outdated}</div>
                    <div class="stat-lbl">Outdated</div>
                </div>
                <div class="stat-card error">
                    <div class="stat-val">${total_vulns}</div>
                    <div class="stat-lbl">Vulnerable</div>
                </div>
                <div class="stat-card depr">
                    <div class="stat-val">${deprecated}</div>
                    <div class="stat-lbl">Deprecated</div>
                </div>
                <div class="stat-card muted">
                    <div class="stat-val">${suppressed_vulns}</div>
                    <div class="stat-lbl">Suppressed</div>
                </div>
                <div class="stat-card success">
                    <div class="stat-val">${up_to_date}</div>
                    <div class="stat-lbl">Up-to-date</div>
                </div>
                <div class="stat-card error" style="background-color: rgba(239, 68, 68, 0.05);">
                    <div class="stat-val">${errors}</div>
                    <div class="stat-lbl">Errors</div>
                </div>
            </div>
            
            <!-- SVG Bar Chart -->
            <div>
                ${svg_chart}
            </div>
        </div>
        
        <!-- Controls -->
        <div class="controls-placeholder">
            <div class="controls-toolbar">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search packages..." oninput="onSearchInput()">
                <button id="clearSearch" onclick="clearSearchInput()">&times;</button>
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" data-cat="all" onclick="setCategory('all', event)">All</button>
                
                <div class="filter-group">
                    <button class="filter-btn" data-cat="vulnerable" onclick="setCategory('vulnerable', event)">
                        Vulnerable <span class="chevron-inline">▼</span>
                    </button>
                    <div class="filter-dropdown" id="dropdown-vulnerable">
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="critical" checked onchange="filterPackages()"> <span class="dot crit-dot"></span> Critical</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'critical')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="high" checked onchange="filterPackages()"> <span class="dot high-dot"></span> High</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'high')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="medium" checked onchange="filterPackages()"> <span class="dot med-dot"></span> Medium</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'medium')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="low" checked onchange="filterPackages()"> <span class="dot low-dot"></span> Low</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'low')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="unknown" checked onchange="filterPackages()"> <span class="dot unkn-dot"></span> Unknown</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'unknown')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                    </div>
                </div>
                
                <div class="filter-group">
                    <button class="filter-btn" data-cat="outdated" onclick="setCategory('outdated', event)">
                        Outdated <span class="chevron-inline">▼</span>
                    </button>
                    <div class="filter-dropdown" id="dropdown-outdated">
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="major" checked onchange="filterPackages()"> Major Update</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'major')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="minor" checked onchange="filterPackages()"> Minor Update</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'minor')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="patch" checked onchange="filterPackages()"> Patch Update</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'patch')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                    </div>
                </div>
                
                <button class="filter-btn" data-cat="deprecated" onclick="setCategory('deprecated', event)">Deprecated</button>
                <button class="filter-btn" data-cat="suppressed" onclick="setCategory('suppressed', event)">Suppressed</button>
                <button class="filter-btn" data-cat="error" onclick="setCategory('error', event)">Errors</button>
                
                <div class="filter-group">
                    <button class="filter-btn" data-cat="scope" onclick="setCategory('scope', event)">
                        Scope <span class="chevron-inline">▼</span>
                    </button>
                    <div class="filter-dropdown" id="dropdown-scope">
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="direct" checked onchange="filterPackages()"> Direct</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'direct')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="dev" checked onchange="filterPackages()"> Dev</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'dev')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="transitive" checked onchange="filterPackages()"> Transitive</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'transitive')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                        <div class="dropdown-row">
                            <label><input type="checkbox" value="engine" checked onchange="filterPackages()"> Engine</label>
                            <span class="row-actions">
                                <span class="action-btn" onclick="selectOnly(event, 'engine')">only</span>
                                <span class="action-separator">/</span>
                                <span class="action-btn" onclick="selectAll(event)">all</span>
                            </span>
                        </div>
                    </div>
                </div>
                
                <button class="filter-btn" data-cat="clean" onclick="setCategory('clean', event)">Clean</button>
            </div>
        </div>
    </div>
        
        <!-- Packages List -->
        <div class="packages-list" id="packageContainer">
            <!-- Dynamic cards are rendered here -->
        </div>
    </div>
    
    <script>
        const KEVLAR_REPORT_PACKAGES = ${packages_json_data};
        const KEVLAR_VULNERABILITY_STORE = ${vulns_json_data};
        const SHOW_PROJECT_GLOBALLY = ${show_project_globally};
        const UNIQUE_PROJECT_PATHS = ${unique_project_paths};
        const VULS_ENABLED = ${vuls_enabled};
        
        function renderPackages() {
            const container = document.getElementById('packageContainer');
            if (!container) return;
            
            let htmlBuffer = '';
            
            KEVLAR_REPORT_PACKAGES.forEach((r, i) => {
                const name = r.name;
                const declared = r.declared;
                const installed = r.installed;
                const latest = r.latest;
                const status = r.status;
                const is_deprecated = r.deprecated;
                const error = r.error;
                const dep_type = r.dep_type;
                
                const name_esc = escapeHtml(name);
                const declared_esc = declared ? escapeHtml(declared) : "";
                const installed_esc = escapeHtml(installed);
                const latest_esc = escapeHtml(latest);
                const status_esc = escapeHtml(status);
                const error_esc = escapeHtml(error || '');
                const dep_type_esc = escapeHtml(dep_type);
                
                let project_badge = "";
                if (!SHOW_PROJECT_GLOBALLY && r.project_path) {
                    const proj_path = r.project_path;
                    const tech_val = r.technology || "";
                    project_badge = '<span class="badge badge-project" style="font-family: monospace; text-transform: none; margin-left: 4px;">' + escapeHtml(proj_path) + ' [' + escapeHtml(tech_val) + ']</span>';
                }
                
                let badges = [];
                if (error) {
                    badges.push('<span class="badge badge-error">Error</span>');
                } else if (status === "up-to-date") {
                    badges.push('<span class="badge badge-success">Up-to-date</span>');
                } else if (status.includes("major")) {
                    badges.push('<span class="badge badge-error">Major Update</span>');
                } else if (status === "minor") {
                    badges.push('<span class="badge badge-warning">Minor Update</span>');
                } else if (status === "patch") {
                    badges.push('<span class="badge badge-info">Patch Update</span>');
                } else if (status === "local") {
                    badges.push('<span class="badge badge-info">Verify Local</span>');
                }
                
                if (is_deprecated) {
                    badges.push('<span class="badge badge-depr">Deprecated</span>');
                }
                
                if (r.missing_checksum) {
                    badges.push('<span class="badge badge-warning">No Checksum</span>');
                } else if (r.weak_checksum) {
                    badges.push('<span class="badge badge-warning">Weak Checksum</span>');
                }
                
                if (r.mismatch_checksum) {
                    badges.push('<span class="badge badge-error">Checksum Mismatch</span>');
                }
                
                const pkg_vulns = r.vulnerabilities || [];
                const pkg_suppressed_vulns = r.suppressed_vulnerabilities || [];
                const is_vulnerable = pkg_vulns.length > 0;
                const is_suppressed = pkg_suppressed_vulns.length > 0;
                
                let severities_list = [];
                pkg_vulns.forEach(vid => {
                    const v = KEVLAR_VULNERABILITY_STORE[vid];
                    if (v && v.severity) {
                        severities_list.push(getSeverityLevel(v.severity));
                    }
                });
                const data_severities = severities_list.join(',');
                
                if (is_vulnerable) {
                    let c_cnt = 0, h_cnt = 0, m_cnt = 0, l_cnt = 0, u_cnt = 0;
                    pkg_vulns.forEach(vid => {
                        const v = KEVLAR_VULNERABILITY_STORE[vid];
                        if (v) {
                            const level = getSeverityLevel(v.severity);
                            if (level === "critical") c_cnt++;
                            else if (level === "high") h_cnt++;
                            else if (level === "medium") m_cnt++;
                            else if (level === "low") l_cnt++;
                            else u_cnt++;
                        }
                    });
                    
                    const total_v = pkg_vulns.length;
                    const badge_html = 
                        '<span class="badge badge-vuln-stats" title="' + total_v + ' Vulnerabilities">' +
                            '<svg class="icon-shield" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px; vertical-align: middle;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>' +
                            '<span>' + total_v + ' vuls</span>' +
                        '</span>';
                    badges.push(badge_html);
                    
                    let pills = [];
                    if (c_cnt > 0) pills.push('<span class="sev-pill sev-c">' + c_cnt + ' C</span>');
                    if (h_cnt > 0) pills.push('<span class="sev-pill sev-h">' + h_cnt + ' H</span>');
                    if (m_cnt > 0) pills.push('<span class="sev-pill sev-m">' + m_cnt + ' M</span>');
                    if (l_cnt > 0) pills.push('<span class="sev-pill sev-l">' + l_cnt + ' L</span>');
                    if (u_cnt > 0) pills.push('<span class="sev-pill sev-u">' + u_cnt + ' U</span>');
                    
                    if (pills.length > 0) {
                        badges.push('<div class="vuln-severity-pills">' + pills.join('') + '</div>');
                    }
                }
                
                if (is_suppressed) {
                    badges.push('<span class="badge badge-muted">' + pkg_suppressed_vulns.length + ' Suppressed</span>');
                }
                
                let vuln_details_html = '';
                if (is_vulnerable && VULS_ENABLED) {
                    vuln_details_html += '<div class="section-title">Active Vulnerabilities</div>';
                    
                    const severity_order = {
                        "critical": 4,
                        "high": 3,
                        "medium": 2,
                        "low": 1,
                        "unknown": 0
                    };
                    
                    const sorted_vulns = [...pkg_vulns].sort((a_id, b_id) => {
                        const a = KEVLAR_VULNERABILITY_STORE[a_id];
                        const b = KEVLAR_VULNERABILITY_STORE[b_id];
                        const a_sev = a ? getSeverityLevel(a.severity) : "unknown";
                        const b_sev = b ? getSeverityLevel(b.severity) : "unknown";
                        return (severity_order[b_sev] || 0) - (severity_order[a_sev] || 0);
                    });
                    
                    sorted_vulns.forEach(vid => {
                        const v = KEVLAR_VULNERABILITY_STORE[vid];
                        if (!v) return;
                        
                        const severity = v.severity;
                        const summary = v.summary;
                        const details = v.details || "";
                        
                        const vid_esc = escapeHtml(vid);
                        const severity_esc = escapeHtml(severity);
                        const summary_esc = escapeHtml(summary);
                        const details_esc = escapeHtml(details);
                        
                        const sev_lower = getSeverityLevel(severity);
                        const sev_badge_class = 'sev-' + escapeHtml(sev_lower);
                        
                        let cvss_html = '';
                        // severity is now always a normalized text label (critical/high/medium/low/unknown)
                        const sev_badge_html = '<span class="sev-badge ' + sev_badge_class + '">' + escapeHtml((sev_lower || 'unknown').toUpperCase()) + '</span>';
                        
                        vuln_details_html += 
                            '<div class="vuln-item">' +
                                '<div class="vuln-header">' +
                                    '<span class="vuln-id">' + vid_esc + '</span>' +
                                '</div>' +
                                cvss_html +
                                '<div style="margin-top: 4px; margin-bottom: 8px;">' +
                                    sev_badge_html +
                                '</div>' +
                                '<div class="vuln-summary">' + summary_esc + '</div>' +
                                (details ? '<pre class="vuln-details">' + details_esc + '</pre>' : '') +
                            '</div>';
                    });
                }
                
                let suppressed_details_html = '';
                if (is_suppressed) {
                    suppressed_details_html += '<div class="section-title">Suppressed Vulnerabilities (Ignored)</div>';
                    pkg_suppressed_vulns.forEach(sv => {
                        const vid = sv.id;
                        const v_info = KEVLAR_VULNERABILITY_STORE[vid] || {};
                        const summary = v_info.summary || sv.summary || "";
                        const reason = sv.suppressed_reason || "No reason provided";
                        const justification = sv.justification || "N/A";
                        const expires_at = sv.expires_at || "N/A";
                        const approved_by = sv.approved_by || "";
                        
                        const vid_esc = escapeHtml(vid);
                        const summary_esc = escapeHtml(summary);
                        const reason_esc = escapeHtml(reason);
                        const justification_esc = escapeHtml(justification);
                        const expires_at_esc = escapeHtml(expires_at);
                        const approved_by_esc = escapeHtml(approved_by);
                        
                        const approved_by_html = approved_by_esc ? '<div style="margin-top: 4px; font-size: 12.5px; padding: 0 4px; color: var(--text-muted);"><strong>Approved By:</strong> ' + approved_by_esc + '</div>' : '';
                        
                        suppressed_details_html += 
                            '<div class="suppressed-item">' +
                                '<div class="vuln-header">' +
                                    '<span class="vuln-id">' + vid_esc + '</span>' +
                                    '<span class="suppressed-label">Ignored</span>' +
                                '</div>' +
                                '<div class="vuln-summary">' + summary_esc + '</div>' +
                                '<div class="suppressed-reason"><strong>Reason:</strong> ' + reason_esc + '</div>' +
                                '<div style="margin-top: 6px; font-size: 12.5px; padding: 0 4px; color: var(--text-muted);">' +
                                    '<strong>Justification:</strong> ' + justification_esc +
                                '</div>' +
                                '<div style="margin-top: 4px; font-size: 12.5px; padding: 0 4px; color: var(--text-muted);">' +
                                    '<strong>Expires At:</strong> ' + expires_at_esc +
                                '</div>' +
                                approved_by_html +
                            '</div>';
                    });
                }
                
                let required_by_html = '';
                const required_by = r.required_by || [];
                const is_direct = (declared && dep_type !== 'Transitive');
                if (required_by.length > 0 && !is_direct) {
                    const required_by_esc = required_by.map(rb => escapeHtml(rb));
                    required_by_html = 
                        '<div class="required-by-section">' +
                            '<strong>Required by:</strong> ' + required_by_esc.join(', ') +
                        '</div>';
                }
                
                let notes_warnings_html = '';
                let notes_warnings_list = [];
                if (is_deprecated) {
                    const msg = typeof is_deprecated === 'string' ? is_deprecated : "This package has been deprecated.";
                    notes_warnings_list.push('<div class="note-warning-item"><span class="note-warning-icon">🚫</span> <div><strong>Deprecation Warning:</strong> ' + escapeHtml(msg) + '</div></div>');
                }
                if (error) {
                    notes_warnings_list.push('<div class="note-warning-item"><span class="note-warning-icon">❌</span> <div><strong>Error:</strong> ' + error_esc + '</div></div>');
                }
                if (r.missing_checksum) {
                    notes_warnings_list.push('<div class="note-warning-item"><span class="note-warning-icon">⚠️</span> <div><strong>Security Warning:</strong> Missing integrity checksum in lockfile</div></div>');
                } else if (r.weak_checksum) {
                    notes_warnings_list.push('<div class="note-warning-item"><span class="note-warning-icon">⚠️</span> <div><strong>Security Warning:</strong> Weak checksum (SHA-1) in lockfile</div></div>');
                }
                if (r.mismatch_checksum) {
                    notes_warnings_list.push('<div class="note-warning-item"><span class="note-warning-icon">❌</span> <div><strong>INTEGRITY MISMATCH:</strong> Lockfile checksum does not match official registry checksum!</div></div>');
                }
                
                if (notes_warnings_list.length > 0) {
                    notes_warnings_html = 
                        '<div class="notes-warnings-section">' +
                            '<div class="section-title-inline">' +
                                '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>' +
                                ' Notes & Warnings' +
                            '</div>' +
                            '<div class="notes-warnings-body">' +
                                notes_warnings_list.join('\\n') +
                            '</div>' +
                        '</div>';
                }
                
                let ai_button_html = '';
                const requires_attention = (['major', 'minor', 'patch', 'minor-major', 'patch-major'].includes(status)) || is_deprecated || is_vulnerable;
                if (requires_attention) {
                    ai_button_html = '<button class="btn-ai-prompt" onclick="copiarPromptRemediacionByIndex(' + i + '); event.stopPropagation();">📋 AI Prompt</button>';
                }
                
                let remediation_button_html = '';
                if (r.remediation && is_direct) {
                    remediation_button_html = 
                        '<div class="remediation-section" style="margin-top: 12px; border-top: 1px solid var(--border-color); padding-top: 10px; margin-bottom: 12px;">' +
                            '<div style="font-size: 12px; font-weight: 700; color: var(--success); margin-bottom: 8px;">Remediation:</div>' +
                            '<div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">' +
                                '<button class="btn-remediation" onclick="openRemediationModalByIndex(' + i + '); event.stopPropagation();">' +
                                    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;">' +
                                        '<path d="M12 20h9"></path>' +
                                        '<path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>' +
                                    '</svg>' +
                                    'Show suggested change' +
                                '</button>' +
                                ai_button_html +
                            '</div>' +
                        '</div>';
                } else if (ai_button_html) {
                    remediation_button_html = 
                        '<div class="remediation-section" style="margin-top: 12px; border-top: 1px solid var(--border-color); padding-top: 10px; margin-bottom: 12px;">' +
                            '<div style="font-size: 12px; font-weight: 700; color: var(--success); margin-bottom: 8px;">Remediation Support:</div>' +
                            ai_button_html +
                        '</div>';
                }
                
                let changelog_html = '';
                if (status === "major" || status === "minor-major" || status === "patch-major") {
                    const compare_url = r.compare_url;
                    const releases_url = r.releases_url;
                    let buttons = [];
                    if (compare_url) {
                        buttons.push('<a href="' + escapeHtml(compare_url) + '" target="_blank" class="changelog-btn">Compare Diff</a>');
                    }
                    if (releases_url) {
                        buttons.push('<a href="' + escapeHtml(releases_url) + '" target="_blank" class="changelog-btn">Release Notes</a>');
                    }
                    if (buttons.length > 0) {
                        changelog_html = 
                            '<div class="changelog-section" style="margin-top: 12px; border-top: 1px solid var(--border-color); padding-top: 10px; margin-bottom: 12px;">' +
                                '<div style="font-size: 12px; font-weight: 700; color: var(--warning); margin-bottom: 8px;">Analysis & Migration Links:</div>' +
                                buttons.join('\\n') +
                            '</div>';
                    }
                }
                
                htmlBuffer += 
                    '<div class="package-card" ' +
                         'data-name="' + name_esc + '" ' +
                         'data-status="' + status_esc + '" ' +
                         'data-vulnerable="' + (is_vulnerable ? 'true' : 'false') + '" ' +
                         'data-severities="' + escapeHtml(data_severities) + '" ' +
                         'data-suppressed="' + (is_suppressed ? 'true' : 'false') + '" ' +
                         'data-deprecated="' + (is_deprecated ? 'true' : 'false') + '" ' +
                         'data-error="' + (error ? 'true' : 'false') + '" ' +
                         'data-deptype="' + dep_type_esc.toLowerCase() + '" ' +
                         'id="pkg-' + i + '">' +
                        '<div class="card-header" onclick="toggleDetails(' + i + ')">' +
                            '<div class="header-left">' +
                                '<div class="pkg-title">' +
                                    '<span class="pkg-name">' + name_esc + '</span>' +
                                    '<span class="pkg-type-badge">' + dep_type_esc + '</span>' + project_badge +
                                '</div>' +
                                '<div class="pkg-badges">' +
                                    badges.join(' ') +
                                '</div>' +
                            '</div>' +
                            '<div class="header-right">' +
                                (function() {
                                    const installed = r.installed;
                                    const latest_sm = r.latest_same_major || installed;
                                    const latest_abs = r.latest_absolute || installed;
                                    
                                    let declared_html = '';
                                    if (declared_esc) {
                                        declared_html = '<div class="version-installed" style="margin-bottom: 2px;">' +
                                            '<span class="label">Declared:</span>' +
                                            '<span>' + declared_esc + '</span>' +
                                        '</div>';
                                    }
                                    
                                    let versions_html = '<div class="pkg-versions">' +
                                        declared_html +
                                        '<div class="version-installed">' +
                                            '<span class="label">Installed:</span>' +
                                            '<span>v' + escapeHtml(installed) + '</span>' +
                                        '</div>' +
                                        '<div class="version-chips">';
                                    
                                    if (status === 'up-to-date' || status === 'local') {
                                        versions_html += 
                                            '<span class="v-chip v-chip-ok">' +
                                                '<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 3px;"><polyline points="20 6 9 17 4 12"></polyline></svg>' +
                                                'Up to date' +
                                            '</span>';
                                    } else {
                                        // Safe update available (minor or patch)
                                        if ((status.includes('minor') || status.includes('patch')) && latest_sm !== installed) {
                                            versions_html += 
                                                '<span class="v-chip v-chip-safe" title="Safe update within the same major version">' +
                                                    '<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 3px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>' +
                                                    'Safe: v' + escapeHtml(latest_sm) +
                                                '</span>';
                                        }
                                        // Major update available (requires upgrade to new major)
                                        if (status.includes('major') && latest_abs !== installed) {
                                            versions_html += 
                                                '<span class="v-chip v-chip-major" title="Major update with potential breaking changes">' +
                                                    '<svg viewBox="0 0 24 24" width="10" height="10" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 3px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path></svg>' +
                                                    'Major: v' + escapeHtml(latest_abs) +
                                                '</span>';
                                        }
                                    }
                                    
                                    versions_html += '</div></div>';
                                    return versions_html;
                                })() +
                                '<svg class="chevron" id="chevron-' + i + '" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                                    '<polyline points="6 9 12 15 18 9"></polyline>' +
                                    '</svg>' +
                            '</div>' +
                        '</div>' +
                        '<div class="card-details" id="detail-' + i + '" style="display: none;">' +
                            required_by_html +
                            notes_warnings_html +
                            changelog_html +
                            remediation_button_html +
                            vuln_details_html +
                            suppressed_details_html +
                        '</div>' +
                    '</div>';
            });
            
            container.innerHTML = htmlBuffer;
        }
        
        function getSeverityLevel(severity) {
            if (!severity) return 'unknown';
            const s = severity.toLowerCase();
            if (s.includes('critical')) return 'critical';
            if (s.includes('high')) return 'high';
            if (s.includes('medium')) return 'medium';
            if (s.includes('low')) return 'low';
            return 'unknown';
        }
        
        function openRemediationModalByIndex(i) {
            const r = KEVLAR_REPORT_PACKAGES[i];
            if (r && r.remediation) {
                openRemediationModal(r.remediation);
            }
        }
        
        function escapeJsString(str) {
            if (!str) return '';
            return str.toString()
                      .replace(/\\\\/g, '\\\\\\\\')
                      .replace(/'/g, "\\\\'")
                      .replace(/"/g, '\\\\"')
                      .replace(/\\n/g, '\\\\n')
                      .replace(/\\r/g, '\\\\r');
        }
        
        function copiarPromptRemediacionByIndex(i) {
            const r = KEVLAR_REPORT_PACKAGES[i];
            const name = r.name;
            const status = r.status;
            const is_deprecated = r.deprecated;
            const pkg_vulns = r.vulnerabilities || [];
            const is_vulnerable = pkg_vulns.length > 0;
            const required_by = r.required_by || [];
            
            let alert_types = [];
            let details_parts = [];
            if (is_vulnerable) {
                alert_types.push("Vulnerability");
                let vuln_strings = [];
                pkg_vulns.forEach(vid => {
                    const v = KEVLAR_VULNERABILITY_STORE[vid];
                    if (v) {
                        vuln_strings.push(vid + ': ' + (v.summary || ''));
                    }
                });
                details_parts.push("Vulnerabilities: " + vuln_strings.join('; '));
            }
            if (is_deprecated) {
                alert_types.push("Deprecation");
                const dep_msg = typeof is_deprecated === 'string' ? is_deprecated : "This package has been deprecated.";
                details_parts.push("Deprecation Warning: " + dep_msg);
            }
            if (['major', 'minor', 'patch', 'minor-major', 'patch-major'].includes(status)) {
                alert_types.push("Outdated (" + status.charAt(0).toUpperCase() + status.slice(1) + ")");
                details_parts.push("Outdated: " + status.toUpperCase() + " update available (Latest: " + r.latest + ")");
            }
            
            const alert_type = alert_types.join(', ');
            const details_str = details_parts.join(' | ');
            
            const tech_val = r.technology || "";
            const tech_map = {
                "npm": "Node.js / npm",
                "pip": "Python / pip",
                "nuget": ".NET / NuGet",
                "php": "PHP / Composer",
                "maven": "Java / Maven",
                "go": "Go",
                "rust": "Rust / Crates.io",
                "ruby": "Ruby / RubyGems",
                "gradle": "Java / Gradle",
                "android": "Android / Gradle"
            };
            const ecosystem_name = tech_map[tech_val.toLowerCase()] || tech_val || "Software Development";
            const curr_ver = r.installed ? r.installed : r.declared;
            const latest_sm = r.latest_same_major || r.latest;
            const latest_abs = r.latest_absolute || r.latest;
            
            const proj_path = r.project_path || "";
            const proj_name = proj_path ? proj_path.split(/[\\/]/).pop() || "Project" : "Project";
            const required_by_str = required_by.join(', ');
            
            copiarPromptRemediacion(name, ecosystem_name, curr_ver, latest_sm, latest_abs, alert_type, details_str, proj_name, proj_path, r.dep_type, required_by_str);
        }
        
        // Floating toolbar logic on scroll
        document.addEventListener('DOMContentLoaded', () => {
            renderPackages();
            const toolbar = document.querySelector('.controls-toolbar');
            const placeholder = document.querySelector('.controls-placeholder');
            const pkgList = document.querySelector('.packages-list');
            
            function updatePlaceholderHeight() {
                if (placeholder && toolbar && !toolbar.classList.contains('floating')) {
                    placeholder.style.height = toolbar.offsetHeight + 'px';
                }
            }
            
            // Set initial height
            updatePlaceholderHeight();
            window.addEventListener('resize', updatePlaceholderHeight);
            
            // Observe changes in toolbar height (e.g. wrap on screen resize)
            if (window.ResizeObserver) {
                const ro = new ResizeObserver(() => {
                    updatePlaceholderHeight();
                });
                ro.observe(toolbar);
            }
            
            window.addEventListener('scroll', () => {
                if (!toolbar || !placeholder) return;
                
                const placeholderRect = placeholder.getBoundingClientRect();
                
                if (placeholderRect.top < 20) {
                    toolbar.classList.add('floating');
                    pkgList.classList.add('floating-active');
                } else {
                    toolbar.classList.remove('floating');
                    pkgList.classList.remove('floating-active');
                }
            });

            // Disable empty filter buttons on page load
            const cards = document.querySelectorAll('.package-card');
            const hasVulnerable = Array.from(cards).some(card => card.getAttribute('data-vulnerable') === 'true');
            const hasOutdated = Array.from(cards).some(card => ['major', 'minor', 'patch'].includes(card.getAttribute('data-status')));
            const hasDeprecated = Array.from(cards).some(card => card.getAttribute('data-deprecated') === 'true');
            const hasSuppressed = Array.from(cards).some(card => card.getAttribute('data-suppressed') === 'true');
            const hasErrors = Array.from(cards).some(card => card.getAttribute('data-error') === 'true');
            const hasClean = Array.from(cards).some(card => 
                card.getAttribute('data-status') === 'up-to-date' && 
                card.getAttribute('data-vulnerable') === 'false' && 
                card.getAttribute('data-deprecated') === 'false' && 
                card.getAttribute('data-error') === 'false'
            );
            
            if (!hasVulnerable) {
                const btn = document.querySelector('.filter-btn[data-cat="vulnerable"]');
                if (btn) btn.disabled = true;
            }
            if (!hasOutdated) {
                const btn = document.querySelector('.filter-btn[data-cat="outdated"]');
                if (btn) btn.disabled = true;
            }
            if (!hasDeprecated) {
                const btn = document.querySelector('.filter-btn[data-cat="deprecated"]');
                if (btn) btn.disabled = true;
            }
            if (!hasSuppressed) {
                const btn = document.querySelector('.filter-btn[data-cat="suppressed"]');
                if (btn) btn.disabled = true;
            }
            if (!hasErrors) {
                const btn = document.querySelector('.filter-btn[data-cat="error"]');
                if (btn) btn.disabled = true;
            }
            if (!hasClean) {
                const btn = document.querySelector('.filter-btn[data-cat="clean"]');
                if (btn) btn.disabled = true;
            }
        });

        let activeCategories = ['all'];
        
        function selectOnly(event, value) {
            event.preventDefault();
            event.stopPropagation();
            const dropdown = event.target.closest('.filter-dropdown');
            if (dropdown) {
                dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    cb.checked = (cb.value === value);
                });
                filterPackages();
            }
        }
        
        function selectAll(event) {
            event.preventDefault();
            event.stopPropagation();
            const dropdown = event.target.closest('.filter-dropdown');
            if (dropdown) {
                dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    cb.checked = true;
                });
                filterPackages();
            }
        }
        
        function setCategory(cat, event) {
            if (event) {
                event.stopPropagation();
            }
            
            if (cat === 'all') {
                activeCategories = ['all'];
                document.querySelectorAll('.filter-dropdown').forEach(dd => dd.classList.remove('show'));
                document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('dropdown-open'));
                document.querySelectorAll('.filter-dropdown input[type="checkbox"]').forEach(cb => {
                    cb.checked = true;
                });
            } else if (cat === 'clean') {
                activeCategories = ['clean'];
                document.querySelectorAll('.filter-dropdown').forEach(dd => dd.classList.remove('show'));
                document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('dropdown-open'));
                document.querySelectorAll('.filter-dropdown input[type="checkbox"]').forEach(cb => {
                    cb.checked = true;
                });
            } else {
                activeCategories = activeCategories.filter(c => c !== 'all' && c !== 'clean');
                
                if (activeCategories.includes(cat)) {
                    activeCategories = activeCategories.filter(c => c !== cat);
                    const dd = document.getElementById(`dropdown-$${cat}`);
                    if (dd) {
                        dd.classList.remove('show');
                        const group = dd.closest('.filter-group');
                        if (group) {
                            const btn = group.querySelector('.filter-btn');
                            if (btn) btn.classList.remove('dropdown-open');
                        }
                    }
                } else {
                    activeCategories.push(cat);
                    document.querySelectorAll('.filter-dropdown').forEach(dd => dd.classList.remove('show'));
                    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('dropdown-open'));
                    
                    const dd = document.getElementById(`dropdown-$${cat}`);
                    if (dd) {
                        dd.classList.add('show');
                        const group = dd.closest('.filter-group');
                        if (group) {
                            const btn = group.querySelector('.filter-btn');
                            if (btn) btn.classList.add('dropdown-open');
                        }
                    }
                }
                
                if (activeCategories.length === 0) {
                    activeCategories = ['all'];
                }
            }
            
            updateFilterButtonStates();
            filterPackages();
        }
        
        function updateFilterButtonStates() {
            document.querySelectorAll('.filter-btn').forEach(btn => {
                const cat = btn.getAttribute('data-cat');
                if (activeCategories.includes(cat)) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
        }
        
        document.addEventListener('click', function(event) {
            if (!event.target.closest('.filter-group')) {
                document.querySelectorAll('.filter-dropdown').forEach(dd => dd.classList.remove('show'));
                document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('dropdown-open'));
            }
        });
        
        function onSearchInput() {
            const input = document.getElementById('searchInput');
            const clearBtn = document.getElementById('clearSearch');
            if (input.value) {
                clearBtn.style.display = 'block';
            } else {
                clearBtn.style.display = 'none';
            }
            filterPackages();
        }
        
        function clearSearchInput() {
            const input = document.getElementById('searchInput');
            input.value = '';
            document.getElementById('clearSearch').style.display = 'none';
            filterPackages();
            input.focus();
        }
        
        function filterPackages() {
            const searchVal = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.package-card');
            
            const checkedSeverities = Array.from(document.querySelectorAll('#dropdown-vulnerable input[type="checkbox"]:checked')).map(cb => cb.value);
            const checkedOutdated = Array.from(document.querySelectorAll('#dropdown-outdated input[type="checkbox"]:checked')).map(cb => cb.value);
            const checkedScopes = Array.from(document.querySelectorAll('#dropdown-scope input[type="checkbox"]:checked')).map(cb => cb.value);
            
            cards.forEach(card => {
                const name = card.getAttribute('data-name').toLowerCase();
                const status = card.getAttribute('data-status');
                const isVulnerable = card.getAttribute('data-vulnerable') === 'true';
                const cardSeverities = (card.getAttribute('data-severities') || '').split(',').filter(s => s);
                const isSuppressed = card.getAttribute('data-suppressed') === 'true';
                const isDeprecated = card.getAttribute('data-deprecated') === 'true';
                const depType = card.getAttribute('data-deptype');
                const hasError = card.getAttribute('data-error') === 'true';
                
                let matchesCategory = false;
                if (activeCategories.includes('all')) {
                    matchesCategory = true;
                } else {
                    let matchesAll = true;
                    for (const cat of activeCategories) {
                        if (cat === 'vulnerable') {
                            const checkSeverities = cardSeverities.length > 0 ? cardSeverities : ['unknown'];
                            if (!(isVulnerable && checkSeverities.some(s => checkedSeverities.includes(s)))) {
                                matchesAll = false;
                                break;
                            }
                        } else if (cat === 'outdated') {
                            const statusParts = status.split('-');
                            if (!statusParts.some(p => checkedOutdated.includes(p)) && !(checkedOutdated.includes('major') && isDeprecated)) {
                                matchesAll = false;
                                break;
                            }
                        } else if (cat === 'scope') {
                            if (!checkedScopes.includes(depType)) {
                                matchesAll = false;
                                break;
                            }
                        } else if (cat === 'deprecated') {
                            if (!isDeprecated) {
                                matchesAll = false;
                                break;
                            }
                        } else if (cat === 'suppressed') {
                            if (!isSuppressed) {
                                matchesAll = false;
                                break;
                            }
                        } else if (cat === 'error') {
                            if (!hasError) {
                                matchesAll = false;
                                break;
                            }
                        } else if (cat === 'clean') {
                            if (!((status === 'up-to-date' || status === 'local') && !isVulnerable && !isDeprecated && !hasError)) {
                                matchesAll = false;
                                break;
                            }
                        }
                    }
                    matchesCategory = matchesAll;
                }
                
                const matchesSearch = name.includes(searchVal);
                
                if (matchesCategory && matchesSearch) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }
        
        function toggleDetails(idx) {
            const detailEl = document.getElementById('detail-' + idx);
            const chevronEl = document.getElementById('chevron-' + idx);
            if (detailEl.style.display === 'none' || !detailEl.style.display) {
                detailEl.style.display = 'block';
                chevronEl.style.transform = 'rotate(180deg)';
            } else {
                detailEl.style.display = 'none';
                chevronEl.style.transform = 'rotate(0deg)';
            }
        }

        function escapeHtml(text) {
            if (typeof text !== 'string') return '';
            return text.replace(/&/g, '&amp;')
                       .replace(/</g, '&lt;')
                       .replace(/>/g, '&gt;')
                       .replace(/"/g, '&quot;')
                       .replace(/'/g, '&#039;');
        }
        
        function openRemediationModal(info) {
            if (!info) return;
            
            document.getElementById('modal-filepath').textContent = info.display_path || (info.manifest_path + ':' + info.line_number);
            
            const currentContainer = document.getElementById('modal-current-code');
            currentContainer.innerHTML = '';
            info.current_code.forEach(line => {
                const lineDiv = document.createElement('div');
                lineDiv.className = 'diff-line' + (line.is_changed ? ' removed' : '');
                
                const numSpan = document.createElement('span');
                numSpan.className = 'diff-line-num';
                numSpan.textContent = line.line_num;
                
                const contentSpan = document.createElement('span');
                contentSpan.className = 'diff-line-content';
                contentSpan.innerHTML = line.html;
                
                lineDiv.appendChild(numSpan);
                lineDiv.appendChild(contentSpan);
                currentContainer.appendChild(lineDiv);
            });
            
            const suggestedContainer = document.getElementById('modal-suggested-code');
            suggestedContainer.innerHTML = '';
            info.suggested_code.forEach(line => {
                const lineDiv = document.createElement('div');
                lineDiv.className = 'diff-line' + (line.is_changed ? ' added' : '');
                
                const numSpan = document.createElement('span');
                numSpan.className = 'diff-line-num';
                numSpan.textContent = line.line_num;
                
                const contentSpan = document.createElement('span');
                contentSpan.className = 'diff-line-content';
                contentSpan.innerHTML = line.html;
                
                lineDiv.appendChild(numSpan);
                lineDiv.appendChild(contentSpan);
                suggestedContainer.appendChild(lineDiv);
            });
            
            document.getElementById('remediation-modal').style.display = 'flex';
            document.getElementById('modal-backdrop').style.display = 'block';
            
            setTimeout(() => {
                document.getElementById('remediation-modal').classList.add('active');
                document.getElementById('modal-backdrop').classList.add('active');
            }, 10);
        }
        
        function closeRemediationModal() {
            const modal = document.getElementById('remediation-modal');
            const backdrop = document.getElementById('modal-backdrop');
            
            modal.classList.remove('active');
            backdrop.classList.remove('active');
            
            setTimeout(() => {
                modal.style.display = 'none';
                backdrop.style.display = 'none';
            }, 300);
        }
        
        function copiarPromptRemediacion(pkgName, ecosystem, currentVer, latestSameMajor, latestAbsolute, alertType, details, projName, projDir, depType, requiredBy) {
            if (window.event) {
                window.event.stopPropagation();
            }
            
            let targetText = latestAbsolute;
            let tasksIntro = `I want to update this package to version "$${latestAbsolute}". Please perform the following tasks in a detailed and professional manner:`;
            
            if (latestSameMajor && latestAbsolute && latestSameMajor !== latestAbsolute) {
                if (latestSameMajor === currentVer) {
                    targetText = latestAbsolute;
                    tasksIntro = `I want to update this package to version "$${targetText}". Please perform the following tasks in a detailed and professional manner:`;
                } else {
                    targetText = `$${latestSameMajor} or $${latestAbsolute}`;
                    tasksIntro = `I want to update this package to version "$${targetText}". Please perform the following tasks in a detailed and professional manner (taking into account the minor update to "$${latestSameMajor}" vs the major update to "$${latestAbsolute}" in your analysis):`;
                }
            } else if (latestSameMajor && latestSameMajor !== currentVer) {
                targetText = latestSameMajor;
                tasksIntro = `I want to update this package to version "$${targetText}". Please perform the following tasks in a detailed and professional manner:`;
            }
            
            let pkgDesc = `the package "$${pkgName}"`;
            if (depType === 'Transitive' && requiredBy) {
                pkgDesc = `the transitive dependency package "$${pkgName}" (which is required by $${requiredBy})`;
            }
            
            let projectContext = "";
            if (projName && projDir) {
                projectContext = ` (name: $${projName} directory: $${projDir})`;
            }
            
            const promptTexto = `Act as a Senior AppSec Expert and Principal Software Engineer specialized in the $${ecosystem} ecosystem.

I have $${pkgDesc} in my project$${projectContext}, which is currently on version "$${currentVer}".
An alert of type "$${alertType}" has been detected.
Detailed information/Associated alerts:
$${details}

$${tasksIntro}

1. Critically analyze any potential 'Breaking Changes' or destructive impacts when upgrading from version "$${currentVer}" to "$${targetText}".
2. Verify if the target version "$${targetText}" safely resolves the issues and vulnerabilities described in the details above.
3. Provide a step-by-step action plan with the exact console commands to perform the upgrade or mitigate risks if there are disruptive changes or incompatibilities.
4. Check if any other libraries or transitive dependencies will become obsolete, unused, or orphaned as a result of this upgrade, and suggest how to safely clean them up (e.g., pruning unused packages).`;

            navigator.clipboard.writeText(promptTexto).then(() => {
                let btn = null;
                if (window.event) {
                    btn = window.event.currentTarget || window.event.target;
                }
                if (!btn || btn.tagName !== 'BUTTON') {
                    btn = document.activeElement;
                }
                if (btn && btn.tagName !== 'BUTTON') {
                    btn = btn.closest('button');
                }
                if (btn) {
                    const originalText = btn.innerHTML;
                    btn.innerHTML = "Copied!";
                    setTimeout(() => {
                        btn.innerHTML = originalText;
                    }, 2000);
                }
            }).catch(err => {
                console.error('Failed to copy text to clipboard: ', err);
                alert('Failed to copy to clipboard. Please check browser permissions.');
            });
        }
    </script>
    
    <!-- Remediation Modal -->
    <div id="modal-backdrop" class="modal-backdrop" onclick="closeRemediationModal()"></div>
    <div id="remediation-modal" class="remediation-modal">
        <div class="modal-header">
            <h3>Remediation Recommendation</h3>
            <button class="modal-close" onclick="closeRemediationModal()">&times;</button>
        </div>
        <div class="modal-body">
            <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">Declaration Location</div>
            <div class="modal-info-bar">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--primary); flex-shrink: 0; margin-right: 4px;">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                </svg>
                <span id="modal-filepath"></span>
            </div>
            
            <div class="modal-diff-container">
                <div class="diff-box">
                    <div class="diff-box-title current">Current Code</div>
                    <pre class="diff-code" id="modal-current-code"></pre>
                </div>
                <div class="diff-box">
                    <div class="diff-box-title suggested">Suggested Change</div>
                    <pre class="diff-code" id="modal-suggested-code"></pre>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""


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

    # Helper: normalize OSV severity field to simple text level
    def normalize_severity_to_text(severity_raw: str) -> str:
        """Convert a CVSS vector string or plain text to critical/high/medium/low/unknown."""
        if not severity_raw:
            return "unknown"
        s = severity_raw.lower()
        # Plain text labels (already normalized, e.g. from database_specific.severity)
        if s in ("critical", "high", "medium", "moderate", "low", "unknown"):
            return "medium" if s == "moderate" else s
        # Fallback: check if any known severity keywords appear as words
        import re as _re
        if _re.search(r'\bcritical\b', s):
            return "critical"
        if _re.search(r'\bhigh\b', s):
            return "high"
        if _re.search(r'\b(medium|moderate)\b', s):
            return "medium"
        if _re.search(r'\blow\b', s):
            return "low"
        # CVSS v3/v2 vector: parse C: (Confidentiality), I: (Integrity), A: (Availability) metrics
        # Note: string is already lowercased, so metric values are h/l/n/m
        # Use word-boundary-like anchors to avoid /VC: matching for /C:
        def _metric(vector, key):
            # Match /<exact_KEY>:<value> - key must be exact (e.g. /c: not /ac: or /vc:)
            m = _re.search(r'/' + key.lower() + r'(?=[:/])([nhml])', vector)
            if not m:
                # Try pattern: /KEY:VALUE where KEY followed immediately by colon
                m = _re.search(r'(?:^|/)' + key.lower() + r':([nhml])', vector)
            return m.group(1) if m else 'n'
        if 'cvss:3' in s or 'cvss:2' in s:
            c = _metric(s, 'C'); i = _metric(s, 'I'); a = _metric(s, 'A')
            sc = _metric(s, 'S')
            if sc == 'c' and (c == 'h' or i == 'h'):
                return "critical"
            if c == 'h' or i == 'h' or a == 'h':
                return "high"
            if c == 'l' or i == 'l' or a == 'l':
                return "medium"
            return "low"
        if 'cvss:4' in s:
            # CVSS v4 metrics: VC (Vulnerable Confidentiality), VI, VA
            vc = _metric(s, 'VC'); vi = _metric(s, 'VI'); va = _metric(s, 'VA')
            if vc == 'h' and vi == 'h':
                return "critical"
            if vc == 'h' or vi == 'h' or va == 'h':
                return "high"
            if vc == 'l' or vi == 'l' or va == 'l':
                return "medium"
            return "low"
        return "unknown"

    try:
        # Calculate summary statistics
        total = len(results)
        up_to_date = sum(1 for r in results if r["status"] in ("up-to-date", "local"))
        outdated = sum(1 for r in results if r["status"] in ("major", "minor", "patch", "minor-major", "patch-major"))
        deprecated = sum(1 for r in results if r["deprecated"])
        errors = sum(1 for r in results if r["status"] == "error")
        
        total_vulns = 0
        suppressed_vulns = 0
        
        if vuls_enabled:
            total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
            suppressed_vulns = sum(len(r.get("suppressed_vulnerabilities", [])) for r in results)
            
        # Count severities for SVG Chart
        critical = 0
        high = 0
        medium = 0
        low = 0
        unknown = 0
        
        for r in results:
            for v in r.get("vulnerabilities", []):
                level = normalize_severity_to_text(v.get("severity", ""))
                if level == "critical":
                    critical += 1
                elif level == "high":
                    high += 1
                elif level == "medium":
                    medium += 1
                elif level == "low":
                    low += 1
                else:
                    unknown += 1
                    
        max_count = max(critical, high, medium, low, unknown, 1)
        max_h = 130
        
        crit_h = int((critical / max_count) * max_h)
        high_h = int((high / max_count) * max_h)
        med_h = int((medium / max_count) * max_h)
        low_h = int((low / max_count) * max_h)
        unkn_h = int((unknown / max_count) * max_h)
        
        base_y = 180
        crit_y = base_y - crit_h
        high_y = base_y - high_h
        med_y = base_y - med_h
        low_y = base_y - low_h
        unkn_y = base_y - unkn_h
        
        crit_val_y = crit_y - 8 if critical > 0 else base_y - 8
        high_val_y = high_y - 8 if high > 0 else base_y - 8
        med_val_y = med_y - 8 if medium > 0 else base_y - 8
        low_val_y = low_y - 8 if low > 0 else base_y - 8
        unkn_val_y = unkn_y - 8 if unknown > 0 else base_y - 8
        
        # Build SVG Chart
        svg_chart = f"""
        <svg viewBox="0 0 500 220" width="100%" height="220" style="background: #111827; border-radius: 12px; border: 1px solid #374151; padding: 15px; box-sizing: border-box;">
            <!-- Grid lines -->
            <line x1="50" y1="50" x2="450" y2="50" stroke="#374151" stroke-dasharray="3" />
            <line x1="50" y1="115" x2="450" y2="115" stroke="#374151" stroke-dasharray="3" />
            <line x1="50" y1="180" x2="450" y2="180" stroke="#4b5563" />
            
            <!-- CRITICAL -->
            <rect x="75" y="{crit_y}" width="40" height="{crit_h}" fill="url(#grad-crit)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{crit_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{crit_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="95" y="{crit_val_y}" fill="#ef4444" font-size="11" text-anchor="middle" font-weight="bold" font-family="sans-serif">{critical}</text>
            <text x="95" y="198" fill="#9ca3af" font-size="10" text-anchor="middle" font-family="sans-serif">CRITICAL</text>
            
            <!-- HIGH -->
            <rect x="155" y="{high_y}" width="40" height="{high_h}" fill="url(#grad-high)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{high_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{high_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="175" y="{high_val_y}" fill="#f97316" font-size="11" text-anchor="middle" font-weight="bold" font-family="sans-serif">{high}</text>
            <text x="175" y="198" fill="#9ca3af" font-size="10" text-anchor="middle" font-family="sans-serif">HIGH</text>
            
            <!-- MEDIUM -->
            <rect x="235" y="{med_y}" width="40" height="{med_h}" fill="url(#grad-med)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{med_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{med_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="255" y="{med_val_y}" fill="#eab308" font-size="11" text-anchor="middle" font-weight="bold" font-family="sans-serif">{medium}</text>
            <text x="255" y="198" fill="#9ca3af" font-size="10" text-anchor="middle" font-family="sans-serif">MEDIUM</text>
            
            <!-- LOW -->
            <rect x="315" y="{low_y}" width="40" height="{low_h}" fill="url(#grad-low)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{low_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{low_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="335" y="{low_val_y}" fill="#0ea5e9" font-size="11" text-anchor="middle" font-weight="bold" font-family="sans-serif">{low}</text>
            <text x="335" y="198" fill="#9ca3af" font-size="10" text-anchor="middle" font-family="sans-serif">LOW</text>
            
            <!-- UNKNOWN -->
            <rect x="395" y="{unkn_y}" width="40" height="{unkn_h}" fill="url(#grad-unkn)" rx="4" ry="4">
                <animate attributeName="height" from="0" to="{unkn_h}" dur="0.6s" fill="freeze" />
                <animate attributeName="y" from="180" to="{unkn_y}" dur="0.6s" fill="freeze" />
            </rect>
            <text x="415" y="{unkn_val_y}" fill="#9ca3af" font-size="11" text-anchor="middle" font-weight="bold" font-family="sans-serif">{unknown}</text>
            <text x="415" y="198" fill="#9ca3af" font-size="10" text-anchor="middle" font-family="sans-serif">UNKNOWN</text>
            
            <!-- Gradients Definitions -->
            <defs>
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
        unique_project_paths = sorted(list(set(r.get("project_path") for r in results if r.get("project_path"))))
        show_project_globally = len(unique_project_paths) <= 1
        
        project_path_header_html = ""
        if show_project_globally and unique_project_paths:
            single_path = unique_project_paths[0]
            techs = list(sorted(list(set(r.get("technology") for r in results if r.get("project_path") == single_path and r.get("technology")))))
            tech_suffix = f" [{', '.join(techs)}]" if techs else ""
            project_path_header_html = f'<div>Path: <strong>{escape_html(single_path)}{escape_html(tech_suffix)}</strong></div>'
        elif not show_project_globally:
            project_path_header_html = f'<div>Projects: <strong>Multiple ({len(unique_project_paths)})</strong></div>'

        # Extract unique vulnerabilities to global store and build compact JSON packages
        vulnerability_store = {}
        for r in results:
            for v in r.get("vulnerabilities", []):
                vid = v["id"]
                if vid not in vulnerability_store:
                    vulnerability_store[vid] = {
                        "severity": normalize_severity_to_text(v.get("severity", "")),
                        "summary": v.get("summary", ""),
                        "details": v.get("details", "")
                    }
            for sv in r.get("suppressed_vulnerabilities", []):
                vid = sv["id"]
                if vid not in vulnerability_store:
                    vulnerability_store[vid] = {
                        "severity": normalize_severity_to_text(sv.get("severity", "")),
                        "summary": sv.get("summary", ""),
                        "details": sv.get("details", "")
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
            
            dep_type = "Transitive"
            if r.get("is_engine", False):
                dep_type = "Engine"
            elif pkg_data and is_direct_install:
                if name in pkg_data.get("all_direct", {}):
                    dep_type = "Direct"
                elif name in pkg_data.get("devDependencies", {}):
                    dep_type = "Dev"
                    
            if r.get("required_by") and not r.get("is_engine", False) and not is_direct_install:
                dep_type = "Transitive"
                
            pkg_record = {
                "name": name,
                "declared": declared if is_direct_install else "",
                "installed": installed,
                "latest": r["latest"],
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
                        "suppressed_reason": sv.get("suppressed_reason", "No reason provided"),
                        "justification": sv.get("justification", "N/A"),
                        "expires_at": sv.get("expires_at", "N/A"),
                        "approved_by": sv.get("approved_by", "")
                    }
                    for sv in r.get("suppressed_vulnerabilities", [])
                ],
                "required_by": r.get("required_by", []),
                "is_engine": r.get("is_engine", False),
                "technology": r.get("technology", ""),
                "project_path": r.get("project_path", ""),
                "dep_type": dep_type,
                "remediation": r.get("remediation"),
                "compare_url": r.get("compare_url"),
                "releases_url": r.get("releases_url")
            }
            # Remove keys with None, False, empty list, or empty string to optimize JSON payload size
            pkg_record = {k: v for k, v in pkg_record.items() if v is not None and v is not False and v != "" and v != []}
            json_packages.append(pkg_record)

        # Sort results for JSON display: packages with higher severity vulnerabilities first
        if vuls_enabled:
            severity_order = {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
                "unknown": 0
            }
            def get_pkg_max_severity(pkg):
                vuln_ids = pkg.get("vulnerabilities", [])
                sevs = [vulnerability_store[vid]["severity"] for vid in vuln_ids if vid in vulnerability_store]
                if not sevs:
                    return 1
                return -max(severity_order.get(s.lower(), 0) for s in sevs)
            json_packages.sort(key=lambda p: (get_pkg_max_severity(p), p["name"].lower()))
        else:
            json_packages.sort(key=lambda p: p["name"].lower())

        escaped_packages_json = json.dumps(json_packages).replace("<", "\\u003c").replace(">", "\\u003e")
        escaped_vulns_json = json.dumps(vulnerability_store).replace("<", "\\u003c").replace(">", "\\u003e")

        # HTML Master Template rendering
        template_str = HTMLReportTemplateProvider.get_template()
        template = string.Template(template_str)
        
        project_title = escape_html(results[0]["name"].split(":")[0] if (results and ":" in results[0]["name"]) else "Project")
        svg_chart_html = svg_chart if vuls_enabled else '<div style="background:#111827; border-radius:12px; border:1px solid #374151; height:220px; display:flex; align-items:center; justify-content:center; color:#9ca3af; font-size:14px;">Vulnerabilities scan disabled. Run with --vuls to enable charts.</div>'
        
        mapping = {
            "VERSION": VERSION,
            "deprecated": str(deprecated),
            "errors": str(errors),
            "outdated": str(outdated),
            "project_path_header_html": project_path_header_html,
            "suppressed_vulns": str(suppressed_vulns),
            "total": str(total),
            "total_vulns": str(total_vulns),
            "up_to_date": str(up_to_date),
            "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "project_title": project_title,
            "svg_chart": svg_chart_html,
            "packages_json_data": escaped_packages_json,
            "vulns_json_data": escaped_vulns_json,
            "show_project_globally": json.dumps(show_project_globally),
            "unique_project_paths": json.dumps(unique_project_paths),
            "vuls_enabled": json.dumps(vuls_enabled)
        }
        
        html_content = template.safe_substitute(mapping)

        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"{COLOR_GREEN}{ICON_OK} HTML interactive dashboard successfully exported to {filepath}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to export HTML report: {e}{COLOR_RESET}")

# ==============================================================================
# CLI Entrypoint
# ==============================================================================

TECHNOLOGIES = {
    "npm": {
        "files": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "osv_ecosystem": "npm",
        "runner": run_npm_checker
    },
    "pip": {
        "files": ["requirements.txt", "poetry.lock", "Pipfile.lock", "pdm.lock", "pyproject.toml"],
        "osv_ecosystem": "PyPI",
        "runner": run_pip_checker
    },
    "nuget": {
        "files": [".csproj", "packages.config", "project.assets.json"],
        "osv_ecosystem": "NuGet",
        "runner": run_nuget_checker
    },
    "php": {
        "files": ["composer.json", "composer.lock"],
        "osv_ecosystem": "Packagist",
        "runner": run_composer_checker
    },
    "maven": {
        "files": ["pom.xml"],
        "osv_ecosystem": "Maven",
        "runner": run_maven_checker
    },
    "go": {
        "files": ["go.mod"],
        "osv_ecosystem": "Go",
        "runner": run_go_checker
    },
    "rust": {
        "files": ["Cargo.toml", "Cargo.lock"],
        "osv_ecosystem": "crates.io",
        "runner": run_rust_checker
    },
    "ruby": {
        "files": ["Gemfile", "Gemfile.lock"],
        "osv_ecosystem": "RubyGems",
        "runner": run_ruby_checker
    },
    "gradle": {
        "files": ["build.gradle", "build.gradle.kts", "gradle.lockfile", "libs.versions.toml"],
        "osv_ecosystem": "Maven",
        "runner": run_gradle_checker
    },
    "android": {
        "files": ["build.gradle", "build.gradle.kts", "gradle.lockfile", "libs.versions.toml"],
        "osv_ecosystem": "Maven",
        "runner": run_gradle_checker
    }
}

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
        ".git", ".github", ".svn", ".hg", "node_modules", "bower_components",
        "venv", ".venv", "env", ".env", "bin", "obj", "target", "vendor",
        ".gradle", "__pycache__", ".idea", ".vscode", ".agents"
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
        if parts.get("UI") in ("A", "R"):
            ui = "R"
            
        scope = "U"
        if parts.get("SC") in ("H", "L") or parts.get("SI") in ("H", "L") or parts.get("SA") in ("H", "L"):
            scope = "C"
            
        c = parts.get("VC", "N")
        i = parts.get("VI", "N")
        a = parts.get("VA", "N")
        
        v3_vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
        return calculate_cvss3_score(v3_vector)
    except Exception:
        return None

def get_severity_level(vuln):
    """Determines the severity level (critical, high, medium, low, unknown) of a vulnerability."""
    severity = vuln.get("severity", "UNKNOWN")
    sev_upper = severity.upper()
    
    if "CRITICAL" in sev_upper:
        return "critical"
    if "HIGH" in sev_upper:
        return "high"
    if "MEDIUM" in sev_upper or "MODERATE" in sev_upper:
        return "medium"
    if "LOW" in sev_upper:
        return "low"
        
    if "CVSS" in sev_upper or "AV:" in sev_upper:
        m4 = re.search(r'(CVSS:4\.[0-9a-zA-Z/:.]+)', sev_upper)
        if m4:
            vector = m4.group(1)
            score = calculate_cvss4_score_approx(vector)
            if score is not None:
                if score >= 9.0: return "critical"
                elif score >= 7.0: return "high"
                elif score >= 4.0: return "medium"
                elif score >= 0.1: return "low"
                
        m3 = re.search(r'(CVSS:3\.[0-9a-zA-Z/:.]+)', sev_upper)
        if m3:
            vector = m3.group(1)
            score = calculate_cvss3_score(vector)
            if score is not None:
                if score >= 9.0: return "critical"
                elif score >= 7.0: return "high"
                elif score >= 4.0: return "medium"
                elif score >= 0.1: return "low"
                
        vector2 = None
        m2 = re.search(r'(CVSS:2\.[0-9a-zA-Z/:.]+)', sev_upper)
        if m2:
            vector2 = m2.group(1)
        elif "AV:" in sev_upper:
            m_raw2 = re.search(r'(AV:[NAL]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC])', sev_upper)
            if m_raw2:
                vector2 = m_raw2.group(1)
                
        if vector2:
            score = calculate_cvss2_score(vector2)
            if score is not None:
                if score >= 9.0: return "critical"
                elif score >= 7.0: return "high"
                elif score >= 4.0: return "medium"
                elif score >= 0.1: return "low"
                
    return "unknown"

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
                print(f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {severity_counts[sev]} {sev.upper()} vulnerabilities (Limit: {limit}){COLOR_RESET}")
                return True
            elif sev == "unknown" and severity_counts["unknown"] >= limit:
                print(f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {severity_counts['unknown']} UNKNOWN vulnerabilities (Limit: {limit}){COLOR_RESET}")
                return True
    except Exception as e:
        print(f"\n{COLOR_YELLOW}{ICON_WARN} Warning: Failed to parse --fail-on-vulns config '{fail_config}': {e}. Falling back to fail on any vulnerability.{COLOR_RESET}")
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
            print(f"\n{COLOR_YELLOW}{ICON_WARN} Warning: Failed to parse --fail-on-deprecated config '{fail_config}'. Falling back to fail on any deprecated package.{COLOR_RESET}")
            limit = 1
            
    if deprecated_count >= limit:
        print(f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {deprecated_count} deprecated dependency/dependencies (Limit: {limit}){COLOR_RESET}")
        return True
    return False

def check_pipeline_failure_outdated(results, fail_config):
    """Checks if the outdated threshold is breached to fail the build.
    fail_config can be 'any', a number (e.g. '3'), or specific thresholds (e.g. 'major:2,minor:4').
    """
    if not fail_config:
        return False
        
    major_count = sum(1 for r in results if r.get("status") in ("major", "minor-major", "patch-major"))
    minor_count = sum(1 for r in results if r.get("status") in ("minor", "minor-major"))
    patch_count = sum(1 for r in results if r.get("status") in ("patch", "patch-major"))
    total_outdated = sum(1 for r in results if r.get("status") in ("patch", "minor", "major", "minor-major", "patch-major"))
    
    if fail_config == "any":
        if total_outdated > 0:
            print(f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {total_outdated} outdated dependency/dependencies (Limit: 1){COLOR_RESET}")
            return True
        return False
        
    try:
        limit = int(fail_config.strip())
        if total_outdated >= limit:
            print(f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {total_outdated} outdated dependency/dependencies (Limit: {limit}){COLOR_RESET}")
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
            "patch": patch_count
        }
        
        for status_type, limit in thresholds.items():
            if status_type in status_counts and status_counts[status_type] >= limit:
                print(f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {status_counts[status_type]} {status_type.upper()} outdated packages (Limit: {limit}){COLOR_RESET}")
                return True
    except Exception as e:
        print(f"\n{COLOR_YELLOW}{ICON_WARN} Warning: Failed to parse --fail-on-outdated config '{fail_config}': {e}. Falling back to fail on any outdated package.{COLOR_RESET}")
        if total_outdated > 0:
            print(f"\n{COLOR_RED}{ICON_ERROR} CI/CD Threshold Breached: Found {total_outdated} outdated dependency/dependencies (Limit: 1){COLOR_RESET}")
            return True
            
    return False

def check_for_updates():
    """Checks for updates from remote version.md and writes local version.md."""
    url = "https://raw.githubusercontent.com/brunoevn/kevlar-checkdeps/main/version.md"
    print(f"{COLOR_GRAY}{ICON_INFO} Checking for updates from GitHub...{COLOR_RESET}")
    
    latest_version = "Unknown"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Kevlar-CheckDeps-Updater"}
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
    if latest_version not in ("Unknown", "Error"):
        try:
            curr_parts = [int(x) for x in VERSION.split(".")]
            late_parts = [int(x) for x in latest_version.split(".")]
            if late_parts > curr_parts:
                status = "Update Available"
        except Exception:
            if latest_version != VERSION:
                status = "Update Available"
                
    if status == "Update Available":
        print(f"{COLOR_YELLOW}{ICON_WARN} A new version v{latest_version} is available! (Current: v{VERSION}).{COLOR_RESET}")
    elif latest_version not in ("Unknown", "Error"):
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

def main():
    init_colors_and_encoding()
    
    # Check for version/update flags first to avoid required arguments error
    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"kevlar CheckDeps v{VERSION}")
        sys.exit(0)
    elif "--update" in sys.argv:
        check_for_updates()
        sys.exit(0)
        
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Kevlar CheckDeps: Generic Dependency Checker & SCA Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python kevlar.py --tech npm --path ./Backend
  python kevlar.py --tech npm --path ./Frontend --all --show-all
  python kevlar.py --tech npm --output report.json
        """
    )
    
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"kevlar CheckDeps v{VERSION}",
        help="Show program's version number and exit."
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Check for updates from GitHub."
    )
    parser.add_argument(
        "--tech", "-t",
        required=False,
        choices=["npm", "pip", "nuget", "php", "maven", "go", "rust", "ruby", "gradle", "android", "auto"],
        help="The package manager / technology to check (or 'auto' to detect automatically)."
    )
    parser.add_argument(
        "--path", "-p",
        default=".",
        help="The directory path containing the package files (default: current directory)."
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Scan all dependencies (including transitive ones), rather than just direct ones."
    )
    parser.add_argument(
        "--concurrent", "-c",
        type=int,
        default=10,
        help="Number of concurrent network requests (default: 10)."
    )
    parser.add_argument(
        "--output", "-o",
        help="Path to export the report file (supports .json, .md, and .html formats)."
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all dependencies in the output, even if they are up-to-date."
    )
    parser.add_argument(
        "--vuls", "-v",
        action="store_true",
        help="Check security vulnerabilities using the Google OSV database."
    )
    parser.add_argument(
        "--fail-on-vulns",
        nargs="?",
        const="any",
        default=None,
        help="Exit with code 1 if security vulnerabilities are found. Optionally specify thresholds, e.g., 'critical:2,high:4'."
    )
    parser.add_argument(
        "--fail-on-deprecated",
        nargs="?",
        const="any",
        default=None,
        help="Exit with code 1 if deprecated dependencies are found. Optionally specify count threshold (e.g. '3')."
    )
    parser.add_argument(
        "--fail-on-outdated",
        nargs="?",
        const="any",
        default=None,
        help="Exit with code 1 if outdated dependencies are found. Optionally specify count threshold (e.g., '3') or specific types (e.g., 'major:2,minor:4')."
    )
    parser.add_argument(
        "--suppress", "-s",
        default=None,
        help="Path to a JSON file containing vulnerability suppressions (default: look for 'kevlar-suppressions.json')."
    )
    parser.add_argument(
        "--scan-all",
        action="store_true",
        help="Recursively scan the path for multiple projects, automatically detecting their technologies."
    )
    parser.add_argument(
        "--format",
        choices=["html", "json", "sarif", "both"],
        help="Output report format when using --scan-all. 'both' generates HTML and JSON."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detailed stack trace and internal error messages to stdout during execution."
    )
    
    args = parser.parse_args()
    
    global DEBUG_MODE
    DEBUG_MODE = args.debug
    
    # CLI Validation
    if not args.scan_all and not args.tech:
        args.tech = "auto"
        
    if args.scan_all:
        if args.output:
            parser.error("cannot specify --output with --scan-all. The report is automatically generated, format is controlled via --format")
        if not args.format:
            parser.error("the following argument is required when using --scan-all: --format")
    else:
        if args.format:
            parser.error("cannot specify --format without --scan-all. For single-project scan, specify output filename via --output")
            
    if args.scan_all:
        print(f"{COLOR_GRAY}{ICON_INFO} Scanning recursively for projects in: {args.path}{COLOR_RESET}")
        projects = find_projects_recursively(args.path)
        if not projects:
            print(f"{COLOR_YELLOW}{ICON_WARN} No projects detected in path: {args.path}{COLOR_RESET}")
            sys.exit(0)
            
        if args.tech:
            filtered_projects = []
            for project_path, techs in projects:
                if args.tech in techs:
                    filtered_projects.append((project_path, [args.tech]))
            projects = filtered_projects
            if not projects:
                print(f"{COLOR_YELLOW}{ICON_WARN} No projects matching technology '{args.tech}' found in path: {args.path}{COLOR_RESET}")
                sys.exit(0)
                
        print(f"{COLOR_GRAY}{ICON_INFO} Found {len(projects)} project(s) to scan.{COLOR_RESET}")
        
        combined_results = []
        combined_dependencies = {}
        combined_devDependencies = {}
        combined_all_direct = {}
        total_elapsed = 0.0
        sarif_runs = []
        
        original_path = args.path
        original_tech = getattr(args, "tech", None)
        
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
                    apply_vulnerability_suppressions(results, args.suppress, project_path=project_path)
                    results = sorted(results, key=lambda x: x["name"].lower())
                    
                    print_results_table(results, pkg_data, args.show_all, args.vuls)
                    print_summary(results, elapsed, args.vuls)
                    
                    # Generate report file(s) for this project folder
                    rel_path = os.path.relpath(project_path, original_path)
                    if rel_path == ".":
                        proj_dirname = os.path.basename(os.path.abspath(project_path))
                        if not proj_dirname:
                            proj_dirname = "project"
                    else:
                        proj_dirname = rel_path
                        
                    proj_dirname = proj_dirname.replace("/", "_").replace("\\", "_")
                    safe_proj_dirname = re.sub(r'[^\w\-]', '_', proj_dirname)
                    safe_proj_dirname = re.sub(r'_{2,}', '_', safe_proj_dirname).strip("_")
                    
                    if args.format in ("html", "both"):
                        proj_html_filepath = f"report-{safe_proj_dirname}.html"
                        export_html_report(results, pkg_data, proj_html_filepath, args.vuls)
                        
                    if args.format in ("json", "both"):
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
                    print(f"{COLOR_RED}{ICON_ERROR} Error scanning project {project_path} with {tech}: {e}{COLOR_RESET}")
                finally:
                    args.path = original_path
                    args.tech = original_tech
                    
        if not combined_results:
            print(f"{COLOR_YELLOW}{ICON_WARN} No dependency check results collected from projects.{COLOR_RESET}")
            sys.exit(0)
            
        combined_pkg_data = {
            "dependencies": combined_dependencies,
            "devDependencies": combined_devDependencies,
            "all_direct": combined_all_direct
        }
        
        combined_results = sorted(combined_results, key=lambda x: x["name"].lower())
        
        print()
        print("=" * 80)
        print("CONSOLIDATED SUMMARY")
        print("=" * 80)
        print_summary(combined_results, total_elapsed, args.vuls)
        
        if args.format == "sarif" and sarif_runs:
            consolidated_path = "report-consolidated.sarif"
            try:
                consolidated_log = {
                    "$schema": "https://schemastore.org/json/schema/sarif-2.1.0-rtm.5.json",
                    "version": "2.1.0",
                    "runs": sarif_runs
                }
                with open(consolidated_path, "w", encoding="utf-8") as f:
                    json.dump(consolidated_log, f, indent=2)
                print(f"\n{COLOR_GREEN}{ICON_OK} Consolidated SARIF report successfully exported to {consolidated_path}{COLOR_RESET}")
            except Exception as e:
                print(f"\n{COLOR_RED}{ICON_ERROR} Failed to export consolidated SARIF report: {e}{COLOR_RESET}")
        
        failed = False
        if args.fail_on_vulns and check_pipeline_failure(combined_results, args.fail_on_vulns):
            failed = True
        if args.fail_on_deprecated and check_pipeline_failure_deprecated(combined_results, args.fail_on_deprecated):
            failed = True
        if args.fail_on_outdated and check_pipeline_failure_outdated(combined_results, args.fail_on_outdated):
            failed = True
            
        if failed:
            sys.exit(1)
            
        sys.exit(0)
        
    if args.tech == "auto":
        detected_techs = detect_technologies(args.path)
        if not detected_techs:
            print(f"{COLOR_RED}{ICON_ERROR} No technology detected in path: {args.path}{COLOR_RESET}")
            sys.exit(1)
            
        print(f"{COLOR_GRAY}{ICON_INFO} Automatically detected technology: {', '.join(detected_techs)}{COLOR_RESET}")
        
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
                    combined_devDependencies.update(pkg_data_tech.get("devDependencies", {}))
                    combined_all_direct.update(pkg_data_tech.get("all_direct", {}))
        finally:
            args.tech = original_tech
            
        combined_pkg_data = {
            "dependencies": combined_dependencies,
            "devDependencies": combined_devDependencies,
            "all_direct": combined_all_direct
        }
        
        results = combined_results
        pkg_data = combined_pkg_data
        elapsed = total_elapsed
    else:
        tech_info = TECHNOLOGIES.get(args.tech)
        if not tech_info:
            print(f"{COLOR_RED}{ICON_ERROR} Unsupported technology: {args.tech}{COLOR_RESET}")
            sys.exit(1)
            
        results, pkg_data, elapsed = tech_info["runner"](args)
    
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
    
    print_results_table(results, pkg_data, args.show_all, args.vuls)
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
            print(f"{COLOR_YELLOW}{ICON_WARN} Unknown output format. Export supports .json, .md, .html, or .sarif extension.{COLOR_RESET}")
            
    failed = False
    if args.fail_on_vulns and check_pipeline_failure(results, args.fail_on_vulns):
        failed = True
    if args.fail_on_deprecated and check_pipeline_failure_deprecated(results, args.fail_on_deprecated):
        failed = True
    if args.fail_on_outdated and check_pipeline_failure_outdated(results, args.fail_on_outdated):
        failed = True
        
    if failed:
        sys.exit(1)

if __name__ == "__main__":
    main()
