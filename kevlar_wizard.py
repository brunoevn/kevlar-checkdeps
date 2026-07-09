#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Kevlar Vulnerability Suppressions Configuration Wizard
An interactive CLI utility to generate and maintain the kevlar-suppressions.json file.
"""

import os
import sys
import json
import re
import codecs
from datetime import datetime, date, timedelta

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

VERSION = "1.0"

# ANSI escape codes for styling (unified with kevlar.py theme)
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[38;5;203m"       # Sleek soft red
COLOR_YELLOW = "\033[38;5;221m"    # Soft warm yellow
COLOR_GREEN = "\033[38;5;120m"     # Bright fresh green
COLOR_CYAN = "\033[38;5;86m"       # Pastel cyan
COLOR_MAGENTA = "\033[38;5;213m"   # Bright pinkish/magenta
COLOR_GRAY = "\033[38;5;244m"      # Medium gray

ICON_OK = "✔"
ICON_INFO = "ℹ"
ICON_WARN = "⚠"
ICON_ERROR = "✖"
ICON_SHIELD = "🛡️"

ALLOWED_REASONS = [
    "NOT_AFFECTED_BY_VULNERABILITY",
    "VULNERABILITY_MITIGATED_BY_ENVIRONMENT",
    "COMPENSATING_CONTROL_IMPLEMENTED",
    "FALSE_POSITIVE",
    "ACCEPTED_TEMPORARY_RISK"
]

def clean_input(prompt_text):
    """Safe input reading with strip and keyboard interrupt handling."""
    try:
        val = input(prompt_text)
        return val.strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{COLOR_YELLOW}{ICON_WARN} Wizard execution cancelled by user. Exiting.{COLOR_RESET}")
        sys.exit(0)

def print_banner():
    """Prints a beautiful CLI banner."""
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}================================================================================{COLOR_RESET}")
    print(f"   {COLOR_GREEN}{ICON_SHIELD}  Kevlar Vulnerability Suppressions Configuration Wizard v{VERSION}{COLOR_RESET}")
    print(f"                                                             {COLOR_GRAY}by Bruno Nielsen{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}================================================================================{COLOR_RESET}\n")
    print(f"This wizard helps you generate or update {COLOR_BOLD}kevlar-suppressions.json{COLOR_RESET} safely.")
    print("It parses your generated scan report to let you select which alerts to suppress.")

def prompt_choice(prompt_text, options, default=None):
    """Prompts the user to select from a list of options by number."""
    for idx, opt in enumerate(options, 1):
        default_indicator = f" {COLOR_GREEN}[default]{COLOR_RESET}" if default == str(idx) else ""
        print(f"  {COLOR_BOLD}{idx}){COLOR_RESET} {opt}{default_indicator}")
        
    while True:
        choice_prompt = f"{prompt_text}"
        if default:
            choice_prompt += f" [Default: {default}]"
        choice_prompt += ": "
        
        val = clean_input(choice_prompt)
        if not val and default:
            return default
            
        if val.isdigit():
            num = int(val)
            if 1 <= num <= len(options):
                return str(num)
                
        print(f"{COLOR_RED}{ICON_ERROR} Invalid selection. Please enter a number between 1 and {len(options)}.{COLOR_RESET}")

def prompt_string(prompt_text, default=None, min_len=0, custom_validator=None, validator_err_msg=None):
    """Prompts the user for a string and validates it."""
    while True:
        display_prompt = prompt_text
        if default:
            display_prompt += f" [Default: {default}]"
        display_prompt += ": "
        
        val = clean_input(display_prompt)
        if not val and default is not None:
            val = default
            
        if len(val) < min_len:
            print(f"{COLOR_RED}{ICON_ERROR} Input is too short. Minimum length is {min_len} characters.{COLOR_RESET}")
            continue
            
        if custom_validator:
            if not custom_validator(val):
                err = validator_err_msg or "Invalid input format."
                print(f"{COLOR_RED}{ICON_ERROR} {err}{COLOR_RESET}")
                continue
                
        return val

def validate_date_str(s):
    """Checks if a string is a valid date matching YYYY-MM-DD."""
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return False
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except ValueError:
        return False

def validate_date_future(s):
    """Checks if a date is valid and is in the future or today."""
    if not validate_date_str(s):
        return False
    d = datetime.strptime(s, "%Y-%m-%d").date()
    return d >= date.today()

def validate_version_str(s):
    """Checks if a version matches X.Y or X.Y.Z."""
    return bool(re.match(r"^\d+\.\d+(\.\d+)?$", s))

def parse_selection(selection_str, max_val):
    """Parses selections like '1, 2', '1-3', 'all' into a list of 1-based indices."""
    s = selection_str.strip().lower()
    if s == "all":
        return list(range(1, max_val + 1))
        
    indices = set()
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            subparts = [sp.strip() for sp in part.split("-") if sp.strip()]
            if len(subparts) == 2 and subparts[0].isdigit() and subparts[1].isdigit():
                start = int(subparts[0])
                end = int(subparts[1])
                if 1 <= start <= end <= max_val:
                    indices.update(range(start, end + 1))
                else:
                    return None
            else:
                return None
        elif part.isdigit():
            idx = int(part)
            if 1 <= idx <= max_val:
                indices.add(idx)
            else:
                return None
        else:
            return None
            
    return sorted(list(indices))

def validate_suppressions_schema(data):
    """Reuses the validation schema rules logic to ensure final policy is valid."""
    if not isinstance(data, dict):
        raise ValueError("Root must be a JSON object.")
    if "metadata" not in data or "suppressions" not in data:
        raise ValueError("Missing 'metadata' or 'suppressions' root keys.")
        
    metadata = data["metadata"]
    for req_meta in ["version", "last_modified", "approved_by"]:
        if req_meta not in metadata or not isinstance(metadata[req_meta], str) or not metadata[req_meta].strip():
            raise ValueError(f"Metadata field '{req_meta}' must be a non-empty string.")
            
    if not re.match(r"^\d+\.\d+(\.\d+)?$", metadata["version"].strip()):
        raise ValueError("Metadata version format is invalid. Must be 'X.Y' or 'X.Y.Z'.")
        
    try:
        datetime.strptime(metadata["last_modified"].strip(), "%Y-%m-%d")
    except ValueError:
        raise ValueError("Metadata 'last_modified' must be in YYYY-MM-DD format.")
        
    suppressions = data["suppressions"]
    if not isinstance(suppressions, list):
        raise ValueError("'suppressions' must be a list.")
        
    allowed_reasons = set(ALLOWED_REASONS)
    for idx, rule in enumerate(suppressions):
        for req_field in ["id", "package", "reason", "justification", "expires_at"]:
            if req_field not in rule or not isinstance(rule[req_field], str) or not rule[req_field].strip():
                raise ValueError(f"Rule {idx} is missing required non-empty string: '{req_field}'")
                
        reason = rule["reason"].strip()
        if reason not in allowed_reasons:
            raise ValueError(f"Rule {idx} contains an invalid reason: '{reason}'")
            
        expires_at = rule["expires_at"].strip()
        try:
            datetime.strptime(expires_at, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"Rule {idx} contains an invalid expiration date: '{expires_at}'")
            
        for opt in ["ecosystem", "created_by", "approved_by"]:
            if opt in rule and rule[opt] is not None:
                if not isinstance(rule[opt], str) or not rule[opt].strip():
                    raise ValueError(f"Optional field '{opt}' in rule {idx} must be a non-empty string.")

def main():
    print_banner()
    
    # Step 1: Load scan report
    default_report = "report.json"
    print(f"\n{COLOR_BOLD}Step 1: Load scan report file{COLOR_RESET}")
    print("---------------------------------------")
    
    report_path = None
    while True:
        path_input = prompt_string(
            "Enter path to Kevlar JSON report",
            default=default_report if os.path.exists(default_report) else None
        )
        
        if not os.path.exists(path_input):
            print(f"{COLOR_RED}{ICON_ERROR} File not found at: {path_input}{COLOR_RESET}")
            # Scan for other .json files in current directory to help the user
            json_files = [f for f in os.listdir(".") if f.endswith(".json")]
            if json_files:
                print(f"Found other JSON files in current directory: {', '.join(json_files)}")
            continue
            
        try:
            with open(path_input, "r", encoding="utf-8") as f:
                report_data = json.load(f)
            
            if not isinstance(report_data, list):
                print(f"{COLOR_RED}{ICON_ERROR} Invalid format: report.json must contain a list of packages.{COLOR_RESET}")
                continue
                
            report_path = path_input
            break
        except Exception as e:
            print(f"{COLOR_RED}{ICON_ERROR} Failed to parse JSON report file: {e}{COLOR_RESET}")
            
    # Extract vulnerable packages and their vulnerabilities
    vulnerable_items = []
    for pkg in report_data:
        pkg_name = pkg.get("name")
        pkg_tech = pkg.get("technology") or pkg.get("ecosystem") or ""
        
        # Check active vulnerabilities
        vulns = pkg.get("vulnerabilities", [])
        for v in vulns:
            vulnerable_items.append({
                "package": pkg_name,
                "technology": pkg_tech,
                "vuln_id": v.get("id"),
                "severity": v.get("severity") or "UNKNOWN",
                "summary": v.get("summary") or "No summary provided"
            })
            
    if not vulnerable_items:
        print(f"\n{COLOR_GREEN}{ICON_OK} Excellent news! No active vulnerabilities found in report '{report_path}'. Nothing to suppress.{COLOR_RESET}")
        return
        
    print(f"\n{COLOR_GREEN}{ICON_OK} Successfully loaded report. Found {len(vulnerable_items)} vulnerability alerts.{COLOR_RESET}")
    
    # Step 2: Show items and let user select
    print(f"\n{COLOR_BOLD}Step 2: Select vulnerabilities to suppress{COLOR_RESET}")
    print("-----------------------------------------------")
    print(f"{COLOR_GRAY}{'No.':<5} {'Package':<25} {'Ecosystem':<12} {'Vulnerability ID':<18} {'Severity':<10} {'Summary':<40}{COLOR_RESET}")
    print(f"{COLOR_GRAY}" + "─" * 110 + f"{COLOR_RESET}")
    
    for idx, item in enumerate(vulnerable_items, 1):
        pkg_display = item["package"]
        if len(pkg_display) > 24:
            pkg_display = pkg_display[:21] + "..."
        summary_display = item["summary"]
        if len(summary_display) > 38:
            summary_display = summary_display[:35] + "..."
            
        print(f"[{idx:<2}] {pkg_display:<25} {item['technology']:<12} {item['vuln_id']:<18} {item['severity']:<10} {summary_display:<40}")
        
    selected_indices = None
    while True:
        sel_input = prompt_string(
            "\nSelect indices to suppress (e.g. '1, 3', range '1-3', 'all', or 'q' to quit)"
        )
        if sel_input.lower() == "q":
            print(f"{COLOR_YELLOW}{ICON_WARN} Cancelled. Exiting wizard.{COLOR_RESET}")
            return
            
        selected_indices = parse_selection(sel_input, len(vulnerable_items))
        if selected_indices:
            break
            
        print(f"{COLOR_RED}{ICON_ERROR} Invalid selection format. Enter numbers matching the list, e.g., '1, 2', '1-3' or 'all'.{COLOR_RESET}")
        
    print(f"\nSelected {len(selected_indices)} vulnerability alert(s) for suppression.")
    
    # Step 3: Configure each suppression
    new_suppressions = []
    default_expiry = (date.today() + timedelta(days=90)).strftime("%Y-%m-%d")
    
    for count, idx in enumerate(selected_indices, 1):
        item = vulnerable_items[idx - 1]
        print(f"\n{COLOR_CYAN}--------------------------------------------------------------------------------{COLOR_RESET}")
        print(f"Configuring suppression {count} of {len(selected_indices)}: {COLOR_BOLD}{item['package']}{COLOR_RESET} ({item['vuln_id']})")
        print(f"{COLOR_CYAN}--------------------------------------------------------------------------------{COLOR_RESET}")
        
        # 1. Target ID Strategy (Specific or wildcard)
        print(f"\n{COLOR_BOLD}1. Scope Strategy{COLOR_RESET}")
        scope_choice = prompt_choice(
            "Apply suppression to",
            [
                f"The specific vulnerability ID: {item['vuln_id']}",
                f"All vulnerabilities for the '{item['package']}' package (wildcard '*')"
            ],
            default="1"
        )
        suppress_id = item["vuln_id"] if scope_choice == "1" else "*"
        
        # 2. Reason enum
        print(f"\n{COLOR_BOLD}2. Risk Governance Reason{COLOR_RESET}")
        reason_choice = prompt_choice("Select reason categorization", ALLOWED_REASONS)
        reason = ALLOWED_REASONS[int(reason_choice) - 1]
        
        # 3. Justification
        print(f"\n{COLOR_BOLD}3. Technical Justification{COLOR_RESET}")
        justification = prompt_string(
            "Enter detailed justification explaining why this bypass is secure (min 15 chars)",
            min_len=15
        )
        
        # 4. Expiration date
        print(f"\n{COLOR_BOLD}4. Expiration Date{COLOR_RESET}")
        expires_at = prompt_string(
            "Enter expiration date (YYYY-MM-DD)",
            default=default_expiry,
            custom_validator=validate_date_future,
            validator_err_msg="Must be a valid date in the future using format YYYY-MM-DD."
        )
        
        # 5. Reviewers tracking
        print(f"\n{COLOR_BOLD}5. Internal Tracking (Optional){COLOR_RESET}")
        created_by = prompt_string("Created by (author name/username) [Enter to skip]", default="")
        approved_by = prompt_string("Approved by (reviewer name/username) [Enter to skip]", default="")
        
        suppression_rule = {
            "id": suppress_id,
            "package": item["package"],
            "reason": reason,
            "justification": justification,
            "expires_at": expires_at
        }
        if item["technology"]:
            suppression_rule["ecosystem"] = item["technology"]
        if created_by:
            suppression_rule["created_by"] = created_by
        if approved_by:
            suppression_rule["approved_by"] = approved_by
            
        new_suppressions.append(suppression_rule)
        print(f"{COLOR_GREEN}{ICON_OK} Configured rule successfully.{COLOR_RESET}")
        
    # Step 4: Load and merge or save
    print(f"\n{COLOR_BOLD}Step 4: Save policy configurations{COLOR_RESET}")
    print("---------------------------------------")
    
    target_file = "kevlar-suppressions.json"
    existing_data = None
    merge_mode = False
    
    if os.path.exists(target_file):
        print(f"{COLOR_YELLOW}{ICON_WARN} Found an existing '{target_file}' policy file.{COLOR_RESET}")
        save_choice = prompt_choice(
            "Choose save method",
            [
                "Merge new rules into the existing policy (combines rules, updates matches)",
                "Overwrite existing policy completely"
            ],
            default="1"
        )
        if save_choice == "1":
            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
                merge_mode = True
            except Exception as e:
                print(f"{COLOR_RED}{ICON_ERROR} Failed to load existing file. Defaulting to overwrite. Error: {e}{COLOR_RESET}")
                
    final_suppressions = []
    metadata = {}
    
    if merge_mode and existing_data:
        # Load existing suppressions
        final_suppressions = existing_data.get("suppressions", [])
        metadata = existing_data.get("metadata", {})
        
        # Update last modified date
        metadata["last_modified"] = date.today().strftime("%Y-%m-%d")
        
        # Merge new rules
        merged_count = 0
        added_count = 0
        
        for new_rule in new_suppressions:
            new_pkg = new_rule["package"].strip().lower()
            new_id = new_rule["id"].strip().upper()
            new_eco = new_rule.get("ecosystem", "").strip().lower()
            
            # Find duplicate
            duplicate_idx = -1
            for i, old_rule in enumerate(final_suppressions):
                old_pkg = old_rule["package"].strip().lower()
                old_id = old_rule["id"].strip().upper()
                old_eco = old_rule.get("ecosystem", "").strip().lower()
                
                if old_pkg == new_pkg and old_id == new_id and old_eco == new_eco:
                    duplicate_idx = i
                    break
                    
            if duplicate_idx != -1:
                print(f"\n{COLOR_YELLOW}{ICON_WARN} Duplicate rule found in existing file for package '{new_rule['package']}' (vuln: '{new_rule['id']}').{COLOR_RESET}")
                confirm = prompt_string(
                    "Do you want to overwrite it with the new definition? (y/n)",
                    default="y"
                )
                if confirm.lower() in ("y", "yes"):
                    final_suppressions[duplicate_idx] = new_rule
                    merged_count += 1
                    print(f"{COLOR_GREEN}{ICON_OK} Overwrote existing rule.{COLOR_RESET}")
                else:
                    print(f"{COLOR_GRAY}{ICON_INFO} Skipped merging this rule.{COLOR_RESET}")
            else:
                final_suppressions.append(new_rule)
                added_count += 1
                
        print(f"\n{COLOR_GREEN}{ICON_OK} Merged {added_count} new rules, updated {merged_count} existing rules.{COLOR_RESET}")
        
    else:
        # Create fresh policy structure
        final_suppressions = new_suppressions
        print("\nCreating new policy metadata:")
        version = prompt_string(
            "Enter policy version",
            default="1.0.0",
            custom_validator=validate_version_str,
            validator_err_msg="Version must match pattern 'X.Y' or 'X.Y.Z'."
        )
        approved_by = prompt_string(
            "Enter global AppSec approved_by identifier",
            default="AppSec Security Office",
            min_len=2
        )
        
        metadata = {
            "version": version,
            "last_modified": date.today().strftime("%Y-%m-%d"),
            "approved_by": approved_by
        }
        
    # Build complete dict
    output_data = {
        "$schema": "./kevlar-suppressions.schema.json",
        "metadata": metadata,
        "suppressions": final_suppressions
    }
    
    # Validate final compiled schema
    try:
        validate_suppressions_schema(output_data)
    except ValueError as e:
        print(f"\n{COLOR_RED}{ICON_ERROR} Critical error: compiled suppressions file fails schema validation: {e}{COLOR_RESET}")
        print("Saving aborted to protect configuration file integrity.")
        sys.exit(1)
        
    # Save file
    try:
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n{COLOR_GREEN}{COLOR_BOLD}{ICON_OK} Success! Policy file saved successfully to: {target_file}{COLOR_RESET}")
        print(f"Total active suppressions registered: {len(final_suppressions)}")
    except Exception as e:
        print(f"\n{COLOR_RED}{ICON_ERROR} Failed to save policy file: {e}{COLOR_RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
