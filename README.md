# Generic Dependency Checker (`check_deps.py`)

A powerful, fast, and self-contained command-line utility written in Python to scan project dependencies. It identifies **outdated versions**, **deprecation notices**, and **security vulnerabilities** by querying the npm registry and the Google OSV (Open Source Vulnerabilities) database.

Designed with a modular and extensible architecture, it supports checking direct and transitive dependencies and requires **zero external python package installations**.

---

## Key Features

- **Outdated Package Detection**: Compares installed versions against the latest versions in the registry, classifying updates into `Major`, `Minor`, and `Patch` increments.
- **Deprecation Warnings**: Extracts maintainer deprecation notices for exact installed versions.
- **Security Vulnerability Audits**: Queries the public Google OSV database to identify active vulnerabilities, including CVE/GHSA IDs, CVSS vectors, and advisory summaries.
- **Transitive Parent Tracing**: Recursively builds a dependency graph from lockfiles to trace exactly which direct dependency introduced a vulnerable or outdated transitive package (e.g., `Transitive (via mongoose)`).
- **Fast Execution**: Uses Python's `concurrent.futures.ThreadPoolExecutor` to perform network requests concurrently.
- **High Performance Scanning**: Optimizes queries by requesting abbreviated metadata format headers from npm, and checks security advisories in a single `POST /v1/querybatch` request rather than one-by-one.
- **Visual Console Reporting**: Displays findings in a neat, colorized table with summary statistics.
- **Terminal Compatibility Fallback**: Automatically detects standard terminal encoding capabilities, switching seamlessly from Unicode characters to clean ASCII frames to prevent encoding crashes on Windows consoles.
- **JSON & Markdown Exports**: Supports exporting results to formatted Markdown tables or raw JSON datasets for CI/CD pipeline integration.

---

## Installation & Requirements

- **Python**: Version 3.6 or higher.
- **Zero Dependencies**: The script relies **only on Python standard libraries** (`urllib.request`, `concurrent.futures`, `json`, `argparse`, `sys`, `re`, `unicodedata`). No `pip install` is required!

To start, simply download/clone the workspace and run the script:
```powershell
python check_deps.py --help
```

---

## How to Use

### 1. Basic Scan (Direct dependencies only)
By default, the script scans direct dependencies declared in `package.json` inside the current directory (`.`):
```powershell
python check_deps.py --tech npm
```

### 2. Specify Project Directory
Use `--path` (or `-p`) to scan package files in another directory (for example, a backend workspace):
```powershell
python check_deps.py --tech npm --path ./Backend
```

### 3. Scan Security Vulnerabilities
Add the `--vuls` (or `-v`) flag to audit packages against Google's OSV database:
```powershell
python check_deps.py --tech npm --vuls
```

### 4. Scan All Dependencies (Direct + Transitive)
Add the `--all` (or `-a`) flag to scan the entire tree resolved in `package-lock.json` (including nested packages):
```powershell
python check_deps.py --tech npm --all --vuls
```

### 5. Export Report Files
Output findings into structured Markdown (`.md`) or raw JSON (`.json`) files using `--output` (or `-o`):
```powershell
python check_deps.py --tech npm --vuls --output dependency_report.md
```

### 6. Show Up-to-Date Packages
By default, the tool only shows packages that have issues (outdated, deprecated, vulnerable, or errored). Use `--show-all` to list all packages:
```powershell
python check_deps.py --tech npm --show-all
```

---

## CLI Options Reference

| Argument | Short | Default | Description |
| --- | --- | --- | --- |
| `--tech` | `-t` | *Required* | The package manager / technology to check. Currently supports `npm`. |
| `--path` | `-p` | `.` | Directory containing the package files (`package.json` / `package-lock.json`). |
| `--vuls` | `-v` | `False` | Enable security vulnerability queries via Google OSV API. |
| `--all` | `-a` | `False` | Scan all dependencies (including transitives) instead of direct dependencies only. |
| `--concurrent` | `-c` | `10` | Number of concurrent network request threads to run. |
| `--output` | `-o` | `None` | Path to export report file (detects `.json` and `.md` formats). |
| `--show-all` | | `False` | Display all dependencies, even those up-to-date and secure. |

---

## Design Considerations & Behavior

1. **Lockfile Fallback**: If `package-lock.json` is missing, the script extracts the version range declared in `package.json` and compares the minimum possible version against the registry. For precise scans, it is highly recommended to have a lockfile present.
2. **Network Connection**: An active internet connection is required to fetch package definitions from `https://registry.npmjs.org` and vulnerabilities from `https://api.osv.dev`.
3. **Graceful Error Handling**: If a package is not found in the registry (e.g., private package) or a network request fails, the script registers a status `Error` and continues scanning the rest of the list without stopping.
