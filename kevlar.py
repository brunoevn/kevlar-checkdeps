#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dependency Checker Utility
Checks project dependencies for outdated, deprecated, or obsolete versions.
Supports security vulnerability scanning via Google OSV API.
Supports multiple technologies (currently npm).
"""

import os
import sys
import json
import re
import argparse
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import xml.etree.ElementTree as ET

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
            import ctypes
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
    if "utf" not in encoding.lower():
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

def parse_semver(version_str):
    """Parses a version string into (major, minor, patch, prerelease)."""
    if not version_str:
        return (0, 0, 0, '')
    
    # Strip common ranges characters for parsing lower bounds
    clean_str = version_str.strip()
    match = SEMVER_REGEX.search(clean_str)
    if not match:
        # Fallback parsing
        digits = re.findall(r'\d+', clean_str)
        if len(digits) >= 3:
            return (int(digits[0]), int(digits[1]), int(digits[2]), '')
        elif len(digits) == 2:
            return (int(digits[0]), int(digits[1]), 0, '')
        elif len(digits) == 1:
            return (int(digits[0]), 0, 0, '')
        return (0, 0, 0, '')
        
    gd = match.groupdict()
    major = int(gd['major'])
    minor = int(gd['minor'])
    patch = int(gd['patch'])
    prerelease = gd['prerelease'] or ''
    return (major, minor, patch, prerelease)

def compare_versions(v1_str, v2_str):
    """Compares two semver version strings.
    Returns:
       -1 if v1 < v2
        0 if v1 == v2
        1 if v1 > v2
    """
    t1 = parse_semver(v1_str)
    t2 = parse_semver(v2_str)
    
    # Compare major.minor.patch
    if t1[:3] < t2[:3]:
        return -1
    elif t1[:3] > t2[:3]:
        return 1
        
    # Compare prerelease tag (empty is higher than any prerelease tag)
    p1 = t1[3]
    p2 = t2[3]
    if p1 == p2:
        return 0
    if not p1:  # stable is higher
        return 1
    if not p2:  # stable is higher
        return -1
    return -1 if p1 < p2 else 1

def classify_update(installed_str, latest_str):
    """Classifies the update difference between installed and latest version."""
    if installed_str == latest_str:
        return "up-to-date"
        
    cmp = compare_versions(installed_str, latest_str)
    if cmp >= 0:
        return "up-to-date"
        
    t_inst = parse_semver(installed_str)
    t_late = parse_semver(latest_str)
    
    if t_late[0] > t_inst[0]:
        return "major"
    elif t_late[1] > t_inst[1]:
        return "minor"
    else:
        return "patch"

# ==============================================================================
# NPM Checker Logic
# ==============================================================================

def find_npm_files(base_path):
    """Finds package.json and package-lock.json files in path."""
    pkg_path = os.path.join(base_path, "package.json")
    lock_path = os.path.join(base_path, "package-lock.json")
    
    return (pkg_path if os.path.exists(pkg_path) else None,
            lock_path if os.path.exists(lock_path) else None)

def parse_package_json(filepath):
    """Parses package.json to extract direct dependencies."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        dependencies = data.get("dependencies", {})
        dev_dependencies = data.get("devDependencies", {})
        
        return {
            "dependencies": dependencies,
            "devDependencies": dev_dependencies,
            "all_direct": {**dependencies, **dev_dependencies}
        }
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Error reading package.json: {e}{COLOR_RESET}")
        return None

def parse_package_lock(filepath):
    """Parses package-lock.json to extract resolved versions and their parent relations.
    Returns:
        tuple: (resolved, parents) where parents is child_name -> list of parent_names
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        resolved = {}
        parents = {}
        
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
                        
                    # Build parents map
                    deps = pkg_info.get("dependencies", {})
                    dev_deps = pkg_info.get("devDependencies", {})
                    all_deps = {**deps, **dev_deps}
                    for child_name in all_deps.keys():
                        parents.setdefault(child_name, set()).add(pkg_name)
                        
            # Root package dependencies
            root_info = data["packages"].get("") or {}
            root_deps = {**root_info.get("dependencies", {}), **root_info.get("devDependencies", {})}
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
                    parents.setdefault(pkg_name, set()).add(parent_name)
                    
                    if "dependencies" in pkg_info and isinstance(pkg_info["dependencies"], dict):
                        recurse_v1_deps(pkg_info["dependencies"], pkg_name)
                        
            recurse_v1_deps(data["dependencies"])
            
        parents_clean = {k: list(v) for k, v in parents.items()}
        resolved_clean = {k: list(v) for k, v in resolved.items()}
        return resolved_clean, parents_clean
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning reading package-lock.json: {e}{COLOR_RESET}")
        return {}, {}

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

def check_npm_package(target):
    """Queries npm registry for package metadata and checks target version."""
    name = target["name"]
    declared = target["declared"]
    installed_versions = target["installed"]
    
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
            
        url = f"https://registry.npmjs.org/{encoded_name}"
        req = urllib.request.Request(url)
        # Use abbreviated metadata format header
        req.add_header("Accept", "application/vnd.npm.install-v1+json")
        
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            
        latest_version = data.get("dist-tags", {}).get("latest")
        all_versions_meta = data.get("versions", {})
        
        for ver_str in versions_to_check:
            # Strip ranges prefixes to get base version for check
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            ver_meta = all_versions_meta.get(clean_ver) or all_versions_meta.get(ver_str) or {}
            deprecation_msg = ver_meta.get("deprecated")
            
            update_type = "up-to-date"
            if latest_version and clean_ver != "0.0.0":
                update_type = classify_update(clean_ver, latest_version)
                
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": latest_version,
                "status": update_type,
                "deprecated": deprecation_msg,
                "error": None
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

def check_all_targets(targets, max_workers):
    """Executes checks concurrently and renders simple progress."""
    results = []
    total = len(targets)
    completed = 0
    
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(check_npm_package, t): t for t in targets}
        
        for future in as_completed(future_to_target):
            completed += 1
            sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total}] Checking {future_to_target[future]['name']}...{COLOR_RESET}\033[K")
            sys.stdout.flush()
            
            try:
                res_list = future.result()
                results.extend(res_list)
            except Exception as e:
                target = future_to_target[future]
                results.append({
                    "name": target["name"],
                    "declared": target["declared"],
                    "installed": target["installed"][0] if target["installed"] else target["declared"],
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": f"Thread error: {e}"
                })
                
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    return results

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
        
    try:
        url = "https://api.osv.dev/v1/querybatch"
        req = urllib.request.Request(
            url, 
            data=json.dumps({"queries": queries}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            
        results_list = res_data.get("results", [])
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to query OSV database: {e}{COLOR_RESET}")
        return {}
        
    # Process batch results and collect vulnerability IDs to fetch details for
    vuln_ids_to_hydrate = set()
    package_to_vuln_ids = {}
    
    for i, res in enumerate(results_list):
        if i >= len(query_mapping):
            break
        name, ver_str, clean_ver = query_mapping[i]
        vulns = res.get("vulns", [])
        
        if vulns:
            ids = [v["id"] for v in vulns if "id" in v]
            package_to_vuln_ids[(name, ver_str)] = ids
            vuln_ids_to_hydrate.update(ids)
            
    if not vuln_ids_to_hydrate:
        return {}
        
    # Hydrate vulnerability details in parallel
    hydrated_details = {}
    completed = 0
    total_ids = len(vuln_ids_to_hydrate)
    
    print(f"{COLOR_GRAY}[OSV] Hydrating details for {total_ids} vulnerabilities...{COLOR_RESET}")
    
    def fetch_vuln_detail(vuln_id):
        try:
            url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:
                return vuln_id, json.loads(response.read().decode("utf-8"))
        except Exception as e:
            return vuln_id, {"id": vuln_id, "summary": f"Failed to fetch details: {e}", "severity": "UNKNOWN"}
            
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_vuln_detail, vid): vid for vid in vuln_ids_to_hydrate}
        for future in as_completed(futures):
            completed += 1
            sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total_ids}] Fetching {futures[future]}...{COLOR_RESET}\033[K")
            sys.stdout.flush()
            
            vid, detail = future.result()
            hydrated_details[vid] = detail
            
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    
    # Map back to packages
    package_to_vulns = {}
    for (name, ver_str), vids in package_to_vuln_ids.items():
        vuln_list = []
        for vid in vids:
            vuln_data = hydrated_details.get(vid, {})
            # Determine severity
            severity = "UNKNOWN"
            if "severity" in vuln_data and isinstance(vuln_data["severity"], list):
                for sev in vuln_data["severity"]:
                    if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
                        severity = f"CVSS {sev.get('score')}"
                        break
            if severity == "UNKNOWN":
                db_spec = vuln_data.get("database_specific")
                if db_spec and isinstance(db_spec, dict):
                    severity = db_spec.get("severity") or "UNKNOWN"
            
            vuln_list.append({
                "id": vid,
                "summary": vuln_data.get("summary", "No summary provided"),
                "severity": severity,
                "details": vuln_data.get("details", "")
            })
        package_to_vulns[(name, ver_str)] = vuln_list
        
    return package_to_vulns

def find_direct_parents(name, parents_map, direct_packages):
    """Finds which direct dependencies transitively required the given package."""
    if name in direct_packages:
        return {name}
        
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
        print(f"{COLOR_RED}{ICON_ERROR} No package.json or package-lock.json found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    pkg_data = None
    if pkg_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading package.json...{COLOR_RESET}")
        pkg_data = parse_package_json(pkg_file)
        
    lock_data = {}
    parents_data = {}
    if lock_file:
        print(f"{COLOR_GRAY}{ICON_INFO} Reading package-lock.json...{COLOR_RESET}")
        lock_data, parents_data = parse_package_lock(lock_file)
        
    targets = build_check_targets(pkg_data, lock_data, args.all)
    
    if not targets:
        print(f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    start_time = time.time()
    results = check_all_targets(targets, args.concurrent)
    
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
            
    # Resolve transitive dependency parents
    direct_packages = set(pkg_data["all_direct"].keys()) if pkg_data else set()
    for r in results:
        if pkg_data and r["name"] not in direct_packages:
            direct_parents = find_direct_parents(r["name"], parents_data, direct_packages)
            r["required_by"] = sorted(list(direct_parents))
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
        pkg_re = re.compile(r'^\s*([A-Za-z0-9_.-]+)\s*(?:(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9_.-]+))?')
        
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
                
            if " #" in line:
                parts = line.split(" #", 1)
                stripped_line = parts[0].strip()
                comment = parts[1].strip()
            else:
                stripped_line = stripped
                comment = ""
                
            match = pkg_re.match(stripped_line)
            if match:
                pkg_name = match.group(1)
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
        url = f"https://pypi.org/pypi/{encoded_name}/json"
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            
        info = data.get("info", {})
        latest_version = info.get("version")
        releases = data.get("releases", {})
        
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
                    
            update_type = "up-to-date"
            if latest_version and clean_ver != "0.0.0":
                update_type = classify_update(clean_ver, latest_version)
                
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": latest_version,
                "status": update_type,
                "deprecated": yanked_reason,
                "error": None
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
    results = []
    total = len(targets)
    completed = 0
    
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(check_pypi_package, t): t for t in targets}
        
        for future in as_completed(future_to_target):
            completed += 1
            sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total}] Checking {future_to_target[future]['name']}...{COLOR_RESET}\033[K")
            sys.stdout.flush()
            
            try:
                res_list = future.result()
                results.extend(res_list)
            except Exception as e:
                target = future_to_target[future]
                results.append({
                    "name": target["name"],
                    "declared": target["declared"],
                    "installed": target["installed"][0] if target["installed"] else target["declared"],
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": f"Thread error: {e}"
                })
                
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    return results

def run_pip_checker(args):
    """Main orchestrator for pip checker."""
    req_file = os.path.join(args.path, "requirements.txt")
    
    if not os.path.exists(req_file):
        print(f"{COLOR_RED}{ICON_ERROR} No requirements.txt found in: {args.path}{COLOR_RESET}")
        return None, None, 0
        
    print(f"{COLOR_GRAY}{ICON_INFO} Reading requirements.txt...{COLOR_RESET}")
    dependencies, parents_data = parse_requirements_txt(req_file)
    
    if not dependencies:
        print(f"{COLOR_YELLOW}{ICON_WARN} No packages identified to check.{COLOR_RESET}")
        return None, None, 0
        
    targets = []
    for name, spec in sorted(dependencies.items()):
        installed = []
        if spec.startswith("=="):
            installed = [spec[2:]]
            
        targets.append({
            "name": name,
            "declared": spec,
            "installed": installed
        })
        
    start_time = time.time()
    results = check_all_pip_targets(targets, args.concurrent)
    
    # Check vulnerabilities via OSV if requested
    if getattr(args, "vuls", False):
        tech_info = TECHNOLOGIES["pip"]
        osv_vulns = check_osv_vulnerabilities(targets, tech_info["osv_ecosystem"], args.concurrent)
        
        # Attach vulns back to results
        for r in results:
            key = (r["name"], r["installed"])
            r["vulnerabilities"] = osv_vulns.get(key, [])
    else:
        for r in results:
            r["vulnerabilities"] = []
            
    # Resolve transitive dependency parents
    for r in results:
        parents_list = parents_data.get(r["name"], [])
        r["required_by"] = sorted(parents_list)
        
    elapsed = time.time() - start_time
    
    return results, {"dependencies": dependencies, "devDependencies": {}, "all_direct": dependencies}, elapsed

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
                tree = ET.parse(cpm_file)
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
            tree = ET.parse(config_file)
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
            tree = ET.parse(csproj_path)
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
        for target_name, target_libs in targets.items():
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
        for fw_name, fw_info in frameworks.items():
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
        url = f"https://api.nuget.org/v3-flatcontainer/{encoded_name}/index.json"
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            
        versions_list = data.get("versions", [])
        
        stable_versions = []
        for v in versions_list:
            if "-" not in v:
                stable_versions.append(v)
                
        valid_versions = stable_versions if stable_versions else versions_list
        
        def parse_semver_key(v_str):
            m = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?', v_str)
            if m:
                major = int(m.group(1))
                minor = int(m.group(2))
                patch = int(m.group(3)) if m.group(3) else 0
                return (major, minor, patch)
            return (0, 0, 0)
            
        latest_version = None
        if valid_versions:
            sorted_versions = sorted(valid_versions, key=parse_semver_key)
            latest_version = sorted_versions[-1]
            
        for ver_str in versions_to_check:
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            update_type = "up-to-date"
            if latest_version and clean_ver != "0.0.0":
                update_type = classify_update(clean_ver, latest_version)
                
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": latest_version,
                "status": update_type,
                "deprecated": None,
                "error": None
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
    results = []
    total = len(targets)
    completed = 0
    
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(check_nuget_package, t): t for t in targets}
        
        for future in as_completed(future_to_target):
            completed += 1
            sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total}] Checking {future_to_target[future]['name']}...{COLOR_RESET}\033[K")
            sys.stdout.flush()
            
            try:
                res_list = future.result()
                results.extend(res_list)
            except Exception as e:
                target = future_to_target[future]
                results.append({
                    "name": target["name"],
                    "declared": target["declared"],
                    "installed": target["installed"][0] if target["installed"] else target["declared"],
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": f"Thread error: {e}"
                })
                
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    return results

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
        if pkg_data and r["name"] not in direct_packages:
            direct_parents = find_direct_parents(r["name"], parents_data, direct_packages)
            r["required_by"] = sorted(list(direct_parents))
        else:
            r["required_by"] = []
            
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
        url = f"https://repo.packagist.org/p2/{name_lower}.json"
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
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
        
        def parse_semver_key(v_str):
            m = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?', v_str)
            if m:
                major = int(m.group(1))
                minor = int(m.group(2))
                patch = int(m.group(3)) if m.group(3) else 0
                build = int(m.group(4)) if m.group(4) else 0
                return (major, minor, patch, build)
            return (0, 0, 0, 0)
            
        latest_version = None
        if valid_versions:
            sorted_versions = sorted(valid_versions, key=parse_semver_key)
            latest_version = sorted_versions[-1]
            
        for ver_str in versions_to_check:
            clean_ver = ver_str.lstrip("v") if ver_str else "0.0.0"
            if not clean_ver or clean_ver == "0.0.0":
                clean_ver = "0.0.0"
                
            update_type = "up-to-date"
            if latest_version and clean_ver != "0.0.0":
                update_type = classify_update(clean_ver, latest_version)
                
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": latest_version,
                "status": update_type,
                "deprecated": None,
                "error": None
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
    results = []
    total = len(targets)
    completed = 0
    
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(check_composer_package, t): t for t in targets}
        
        for future in as_completed(future_to_target):
            completed += 1
            sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total}] Checking {future_to_target[future]['name']}...{COLOR_RESET}\033[K")
            sys.stdout.flush()
            
            try:
                res_list = future.result()
                results.extend(res_list)
            except Exception as e:
                target = future_to_target[future]
                results.append({
                    "name": target["name"],
                    "declared": target["declared"],
                    "installed": target["installed"][0] if target["installed"] else target["declared"],
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": f"Thread error: {e}"
                })
                
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    return results

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
        if r["name"] not in direct_packages:
            direct_parents = find_direct_parents(r["name"], parents_data, direct_packages)
            r["required_by"] = sorted(list(direct_parents))
        else:
            r["required_by"] = []
            
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

def find_all_maven_poms(root_pom_path):
    """Recursively finds all module pom.xml files declared in a parent pom.xml."""
    poms = [os.path.abspath(root_pom_path)]
    root_dir = os.path.dirname(os.path.abspath(root_pom_path))
    
    try:
        tree = ET.parse(root_pom_path)
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
                    module_pom = os.path.join(root_dir, module_path, "pom.xml")
                    if os.path.exists(module_pom):
                        poms.extend(find_all_maven_poms(module_pom))
    except Exception:
        pass
        
    seen = set()
    unique_poms = []
    for p in poms:
        if p not in seen:
            seen.add(p)
            unique_poms.append(p)
            
    return unique_poms

def parse_maven_pom(filepath, parent_dep_mgmt=None):
    """Parses Maven pom.xml for direct dependencies, interpolating properties and dependencyManagement."""
    dependencies = {}
    if parent_dep_mgmt is None:
        parent_dep_mgmt = {}
        
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        ns = ""
        if "}" in root.tag:
            ns = root.tag.split("}")[0].lstrip("{")
        prefix = f"{{{ns}}}" if ns else ""
        
        # Parse properties
        properties = {}
        props_elem = root.find(f"{prefix}properties")
        if props_elem is not None:
            for elem in props_elem:
                tag_local = elem.tag.split("}")[-1]
                properties[f"${{{tag_local}}}"] = (elem.text or "").strip()
                
        properties["${project.version}"] = (root.findtext(f"{prefix}version") or "").strip()
        properties["${project.groupId}"] = (root.findtext(f"{prefix}groupId") or "").strip()
        
        parent_elem = root.find(f"{prefix}parent")
        if parent_elem is not None:
            if not properties["${project.version}"]:
                properties["${project.version}"] = (parent_elem.findtext(f"{prefix}version") or "").strip()
            if not properties["${project.groupId}"]:
                properties["${project.groupId}"] = (parent_elem.findtext(f"{prefix}groupId") or "").strip()
                
        # Parse local dependencyManagement
        local_dep_mgmt = parse_maven_dependency_management(root, prefix, properties)
        merged_dep_mgmt = {**parent_dep_mgmt, **local_dep_mgmt}
        
        # Parse active dependencies
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
                        elif coord in merged_dep_mgmt:
                            version = merged_dep_mgmt[coord]
                            
                        dependencies[coord] = version
                        
    except Exception as e:
        print(f"{COLOR_YELLOW}{ICON_WARN} Warning parsing pom.xml: {e}{COLOR_RESET}")
        
    return dependencies

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
        url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/maven-metadata.xml"
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            xml_data = response.read()
            
        root = ET.fromstring(xml_data)
        
        versions_list = []
        versioning_elem = root.find("versioning")
        if versioning_elem is not None:
            versions_elem = versioning_elem.find("versions")
            if versions_elem is not None:
                for v in versions_elem.findall("version"):
                    if v.text:
                        versions_list.append(v.text.strip())
                        
        stable_versions = []
        for v in versions_list:
            v_lower = v.lower()
            if not any(x in v_lower for x in ("-", "alpha", "beta", "rc", "m", "cr", "dev")):
                stable_versions.append(v)
                
        valid_versions = stable_versions if stable_versions else versions_list
        
        def parse_semver_key(v_str):
            m = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?', v_str)
            if m:
                major = int(m.group(1))
                minor = int(m.group(2))
                patch = int(m.group(3)) if m.group(3) else 0
                build = int(m.group(4)) if m.group(4) else 0
                return (major, minor, patch, build)
            m_digits = re.match(r'^(\d+)$', v_str)
            if m_digits:
                return (int(m_digits.group(1)), 0, 0, 0)
            return (0, 0, 0, 0)
            
        latest_version = None
        if valid_versions:
            sorted_versions = sorted(valid_versions, key=parse_semver_key)
            latest_version = sorted_versions[-1]
            
        for ver_str in versions_to_check:
            clean_ver = re.sub(r'^[^\d]*', '', ver_str) if ver_str else "0.0.0"
            if not clean_ver:
                clean_ver = "0.0.0"
                
            update_type = "up-to-date"
            if latest_version and clean_ver != "0.0.0":
                update_type = classify_update(clean_ver, latest_version)
                
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": latest_version,
                "status": update_type,
                "deprecated": None,
                "error": None
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
    results = []
    total = len(targets)
    completed = 0
    
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(check_maven_package, t): t for t in targets}
        
        for future in as_completed(future_to_target):
            completed += 1
            sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total}] Checking {future_to_target[future]['name']}...{COLOR_RESET}\033[K")
            sys.stdout.flush()
            
            try:
                res_list = future.result()
                results.extend(res_list)
            except Exception as e:
                target = future_to_target[future]
                results.append({
                    "name": target["name"],
                    "declared": target["declared"],
                    "installed": target["installed"][0] if target["installed"] else target["declared"],
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": f"Thread error: {e}"
                })
                
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    return results

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
        
    print(f"{COLOR_GRAY}{ICON_INFO} Resolving Maven module tree...{COLOR_RESET}")
    all_poms = find_all_maven_poms(manifest)
    
    if len(all_poms) > 1:
        print(f"{COLOR_GRAY}{ICON_INFO} Multi-module project detected. Found {len(all_poms)} modules.{COLOR_RESET}")
        
    # 1. Parse root pom.xml for centralized dependencyManagement versions
    root_dep_mgmt = {}
    try:
        tree = ET.parse(manifest)
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
        pom_deps = parse_maven_pom(pom, root_dep_mgmt)
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
        url = f"https://proxy.golang.org/{escaped_name}/@v/list"
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_data = response.read().decode("utf-8")
            
        versions_list = [v.strip() for v in resp_data.split("\n") if v.strip()]
        
        stable_versions = []
        for v in versions_list:
            v_lower = v.lower()
            if not any(x in v_lower for x in ("-", "alpha", "beta", "rc", "dev")):
                clean_v = v.split("+")[0]
                stable_versions.append((v, clean_v))
                
        valid_versions = stable_versions if stable_versions else [(v, v.split("+")[0]) for v in versions_list]
        
        def parse_semver_key(v_tuple):
            v_str = v_tuple[1].lstrip("v")
            m = re.match(r'^(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?', v_str)
            if m:
                major = int(m.group(1))
                minor = int(m.group(2))
                patch = int(m.group(3)) if m.group(3) else 0
                build = int(m.group(4)) if m.group(4) else 0
                return (major, minor, patch, build)
            return (0, 0, 0, 0)
            
        latest_version = None
        if valid_versions:
            sorted_versions = sorted(valid_versions, key=parse_semver_key)
            latest_version = sorted_versions[-1][0]
            
        for ver_str in versions_to_check:
            clean_ver = ver_str.lstrip("v").split("+")[0] if ver_str else "0.0.0"
            clean_latest = latest_version.lstrip("v").split("+")[0] if latest_version else "0.0.0"
            
            update_type = "up-to-date"
            if latest_version and clean_ver != "0.0.0":
                update_type = classify_update(clean_ver, clean_latest)
                
            results.append({
                "name": name,
                "declared": declared,
                "installed": ver_str,
                "latest": latest_version,
                "status": update_type,
                "deprecated": None,
                "error": None
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
    results = []
    total = len(targets)
    completed = 0
    
    print(f"{COLOR_BOLD}{COLOR_CYAN}Checking {total} packages...{COLOR_RESET}\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(check_go_package, t): t for t in targets}
        
        for future in as_completed(future_to_target):
            completed += 1
            sys.stdout.write(f"\r{COLOR_GRAY}[Progress: {completed}/{total}] Checking {future_to_target[future]['name']}...{COLOR_RESET}\033[K")
            sys.stdout.flush()
            
            try:
                res_list = future.result()
                results.extend(res_list)
            except Exception as e:
                target = future_to_target[future]
                results.append({
                    "name": target["name"],
                    "declared": target["declared"],
                    "installed": target["installed"][0] if target["installed"] else target["declared"],
                    "latest": None,
                    "status": "error",
                    "deprecated": None,
                    "error": f"Thread error: {e}"
                })
                
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    return results

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
# Output Formatting and Reporting
# ==============================================================================

def get_char_width(char):
    """Returns visual terminal width of a character."""
    if char in ("🚫", "🛡️", "🛡"):
        return 2
    import unicodedata
    w = unicodedata.east_asian_width(char)
    if w in ('W', 'F'):
        return 2
    if ord(char) > 0xffff:
        return 2
    return 1

def visual_len(s):
    """Calculates visual terminal length of a string, ignoring ANSI codes."""
    clean_s = re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', s)
    return sum(get_char_width(c) for c in clean_s)

def pad_string(text, width, align="left"):
    """Pads a string (potentially containing ANSI codes and wide chars) to target width."""
    vlen = visual_len(text)
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
    
    hdr_name = pad_string(f" {col_name}", w_name, align="left")
    hdr_type = pad_string(col_type, w_type, align="center")
    hdr_dec = pad_string(col_dec, w_dec, align="center")
    hdr_inst = pad_string(col_inst, w_inst, align="center")
    hdr_latest = pad_string(col_latest, w_latest, align="center")
    hdr_status = pad_string(col_status, w_status, align="center")
    hdr_vuls = pad_string(col_vuls, w_vuls, align="center")
    
    if vuls_enabled:
        print(f"{t['vertical']}{hdr_name}{t['vertical']}{hdr_type}{t['vertical']}{hdr_dec}{t['vertical']}{hdr_inst}{t['vertical']}{hdr_latest}{t['vertical']}{hdr_status}{t['vertical']}{hdr_vuls}{t['vertical']}")
    else:
        print(f"{t['vertical']}{hdr_name}{t['vertical']}{hdr_type}{t['vertical']}{hdr_dec}{t['vertical']}{hdr_inst}{t['vertical']}{hdr_latest}{t['vertical']}{hdr_status}{t['vertical']}")
        
    print(border_mid)
    
    for r in filtered_results:
        dep_type = "Transitive"
        if pkg_data:
            if r["name"] in pkg_data.get("dependencies", {}):
                dep_type = "Direct"
            elif r["name"] in pkg_data.get("devDependencies", {}):
                dep_type = "Dev"
        if r.get("required_by"):
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
            
        if r["deprecated"]:
            status_display = "Deprecated"
            color = COLOR_MAGENTA
            icon = ICON_DEPRECATED
            
        styled_status = f"{color}{icon} {status_display}{COLOR_RESET}"
        
        name_cell = pad_string(f" {r['name']}", w_name, align="left")
        type_cell = pad_string(dep_type, w_type, align="center")
        dec_cell = pad_string(r['declared'] or 'N/A', w_dec, align="center")
        inst_cell = pad_string(r['installed'] or 'N/A', w_inst, align="center")
        latest_cell = pad_string(r['latest'] or 'N/A', w_latest, align="center")
        status_cell = pad_string(styled_status, w_status, align="center")
        
        if vuls_enabled:
            vuls_list = r.get("vulnerabilities", [])
            vuls_count = len(vuls_list)
            if vuls_count > 0:
                styled_vuls = f"{COLOR_RED}{COLOR_BOLD}{vuls_count}{COLOR_RESET}"
            else:
                styled_vuls = f"{COLOR_GREEN}{ICON_OK}{COLOR_RESET}" if ICON_OK == "✔" else f"{COLOR_GREEN}0{COLOR_RESET}"
            vuls_cell = pad_string(styled_vuls, w_vuls, align="center")
            
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
            
    if notes_to_print:
        print(f"\n{COLOR_BOLD}Notes & Warnings:{COLOR_RESET}")
        for note in notes_to_print:
            print(note)
            
    # Print security vulnerabilities details section
    if vuls_enabled:
        vuls_to_print = []
        for r in filtered_results:
            vuls_list = r.get("vulnerabilities", [])
            if vuls_list:
                vuls_to_print.append((r["name"], r["installed"], vuls_list, r.get("required_by", [])))
                
        if vuls_to_print:
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

def print_summary(results, elapsed_time, vuls_enabled=False):
    """Prints checks run count and categorization breakdown."""
    total = len(results)
    up_to_date = sum(1 for r in results if r["status"] == "up-to-date")
    patch = sum(1 for r in results if r["status"] == "patch")
    minor = sum(1 for r in results if r["status"] == "minor")
    major = sum(1 for r in results if r["status"] == "major")
    deprecated = sum(1 for r in results if r["deprecated"])
    errors = sum(1 for r in results if r["status"] == "error")
    
    print(f"\n{COLOR_BOLD}{COLOR_CYAN}Summary Report:{COLOR_RESET}")
    print(f"  Checked:     {total} packages in {elapsed_time:.2f}s")
    print(f"  Up-to-date:  {COLOR_GREEN}{up_to_date}{COLOR_RESET}")
    print(f"  Outdated:    {COLOR_YELLOW}{patch + minor + major}{COLOR_RESET} (Patch: {COLOR_CYAN}{patch}{COLOR_RESET}, Minor: {COLOR_YELLOW}{minor}{COLOR_RESET}, Major: {COLOR_RED}{major}{COLOR_RESET})")
    if deprecated > 0:
        print(f"  Deprecated:  {COLOR_MAGENTA}{deprecated}{COLOR_RESET}")
    if errors > 0:
        print(f"  Errors:      {COLOR_RED}{errors}{COLOR_RESET}")
        
    if vuls_enabled:
        total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
        vuln_pkg_count = sum(1 for r in results if r.get("vulnerabilities"))
        if total_vulns > 0:
            print(f"  Sec Vulnerabilities: {COLOR_RED}{COLOR_BOLD}{total_vulns}{COLOR_RESET} (in {vuln_pkg_count} packages)")
        else:
            print(f"  Sec Vulnerabilities: {COLOR_GREEN}0{COLOR_RESET}")
    print()

def export_json_report(results, filepath):
    """Exports results as raw JSON data."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"{COLOR_GREEN}{ICON_OK} JSON report successfully exported to {filepath}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to export JSON report: {e}{COLOR_RESET}")

def export_markdown_report(results, pkg_data, filepath, vuls_enabled=False):
    """Exports results as a clean Markdown document."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# Dependency Status Report\n\n")
            f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Write summary
            total = len(results)
            up_to_date = sum(1 for r in results if r["status"] == "up-to-date")
            patch = sum(1 for r in results if r["status"] == "patch")
            minor = sum(1 for r in results if r["status"] == "minor")
            major = sum(1 for r in results if r["status"] == "major")
            deprecated = sum(1 for r in results if r["deprecated"])
            errors = sum(1 for r in results if r["status"] == "error")
            
            f.write("## Summary\n\n")
            f.write(f"- **Total Checked**: {total}\n")
            f.write(f"- **Up-to-date**: {up_to_date}\n")
            f.write(f"- **Outdated**: {patch + minor + major} (Patch: {patch}, Minor: {minor}, Major: {major})\n")
            if deprecated:
                f.write(f"- **Deprecated**: {deprecated}\n")
            if errors:
                f.write(f"- **Errors**: {errors}\n")
                
            if vuls_enabled:
                total_vulns = sum(len(r.get("vulnerabilities", [])) for r in results)
                vuln_pkg_count = sum(1 for r in results if r.get("vulnerabilities"))
                f.write(f"- **Security Vulnerabilities**: {total_vulns} found in {vuln_pkg_count} packages\n")
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
                if pkg_data:
                    if r["name"] in pkg_data.get("dependencies", {}):
                        dep_type = "Direct"
                    elif r["name"] in pkg_data.get("devDependencies", {}):
                        dep_type = "Dev"
                        
                if r.get("required_by"):
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
                    
                if r["deprecated"]:
                    status_display = "🚫 Deprecated"
                    note = f"Deprecation Warning: {r['deprecated']}"
                else:
                    note = ""
                    
                if vuls_enabled:
                    vuls_count = len(r.get("vulnerabilities", []))
                    vuls_str = f"⚠️ **{vuls_count}**" if vuls_count > 0 else "✅"
                    f.write(f"| `{r['name']}` | {dep_type} | `{r['declared'] or 'N/A'}` | `{r['installed'] or 'N/A'}` | `{r['latest'] or 'N/A'}` | {status_display} | {vuls_str} | {note} |\n")
                else:
                    f.write(f"| `{r['name']}` | {dep_type} | `{r['declared'] or 'N/A'}` | `{r['installed'] or 'N/A'}` | `{r['latest'] or 'N/A'}` | {status_display} | {note} |\n")
            
            # Write detailed security section
            if vuls_enabled:
                vuls_list_total = []
                for r in results:
                    v_list = r.get("vulnerabilities", [])
                    if v_list:
                        vuls_list_total.append((r["name"], r["installed"], v_list, r.get("required_by", [])))
                        
                if vuls_list_total:
                    f.write("\n## Security Vulnerabilities Details\n\n")
                    for name, ver, v_list, required_by in vuls_list_total:
                        parent_suffix = f" (via {', '.join(required_by)})" if required_by else ""
                        f.write(f"### `{name}@{ver}`{parent_suffix} ({len(v_list)} vulnerabilities)\n\n")
                        for vuln in v_list:
                            f.write(f"- **{vuln['id']}** [{vuln['severity']}]: {vuln['summary']}\n")
                            if vuln.get("details"):
                                details_escaped = vuln['details'].replace('\n', '\n> ')
                                f.write(f"  > {details_escaped}\n\n")
                            else:
                                f.write("\n")
                                
        print(f"{COLOR_GREEN}{ICON_OK} Markdown report successfully exported to {filepath}{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}{ICON_ERROR} Failed to export Markdown report: {e}{COLOR_RESET}")

# ==============================================================================
# CLI Entrypoint
# ==============================================================================

TECHNOLOGIES = {
    "npm": {
        "files": ["package.json", "package-lock.json"],
        "osv_ecosystem": "npm",
        "runner": run_npm_checker
    },
    "pip": {
        "files": ["requirements.txt"],
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
    }
}

def calculate_cvss3_score(vector_str):
    """Calculates base CVSS v3.x score from a vector string."""
    try:
        parts = {p.split(":")[0]: p.split(":")[1] for p in vector_str.split("/") if ":" in p}
        
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
        
    if "CVSS" in sev_upper:
        m = re.search(r'(CVSS:3\.[0-9a-zA-Z/:.]+)', sev_upper)
        if m:
            vector = m.group(1)
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

def print_banner():
    banner = f"""{COLOR_BOLD}{COLOR_CYAN}
 _  __ _____ __     __ _        _    ____  
| |/ /| ____|\\ \\   / /| |      / \\  |  _ \\ 
| ' / |  _|   \\ \\ / / | |     / _ \\ | |_) |
| . \\ | |___   \\ V /  | |___ / ___ \\|  _ < 
|_|\\_\\|_____|   \\_/   |_____/_/   \\_\\_| \\_\\  {COLOR_GRAY}By Bruno Nielsen{COLOR_RESET}
"""
    print(banner)

def main():
    init_colors_and_encoding()
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
        "--tech", "-t",
        required=True,
        choices=["npm", "pip", "nuget", "php", "maven", "go"],
        help="The package manager / technology to check."
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
        help="Path to export the report file (supports .json and .md formats)."
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
    
    args = parser.parse_args()
    
    tech_info = TECHNOLOGIES.get(args.tech)
    if not tech_info:
        print(f"{COLOR_RED}{ICON_ERROR} Unsupported technology: {args.tech}{COLOR_RESET}")
        sys.exit(1)
        
    results, pkg_data, elapsed = tech_info["runner"](args)
    
    if not results:
        sys.exit(0)
        
    # Sort packages alphabetically (A-Z)
    results = sorted(results, key=lambda x: x["name"].lower())
        
    # Render Output
    print_results_table(results, pkg_data, args.show_all, args.vuls)
    print_summary(results, elapsed, args.vuls)
    
    # Export Report
    if args.output:
        if args.output.lower().endswith(".json"):
            export_json_report(results, args.output)
        elif args.output.lower().endswith(".md"):
            export_markdown_report(results, pkg_data, args.output, args.vuls)
        else:
            print(f"{COLOR_YELLOW}{ICON_WARN} Unknown output format. Export supports .json or .md extension.{COLOR_RESET}")
            
    # Check if pipeline should fail
    if args.fail_on_vulns and check_pipeline_failure(results, args.fail_on_vulns):
        sys.exit(1)

if __name__ == "__main__":
    main()
