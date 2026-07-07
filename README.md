# Kevlar CheckDeps (`kevlar.py`)

A powerful, fast, and self-contained command-line utility written in Python to scan project dependencies. It identifies **outdated versions**, **deprecation notices** (yanked packages), and **security vulnerabilities** by querying package registries (npm/PyPI/NuGet/Packagist/Maven Central/Go Proxy/crates.io/RubyGems) and the Google OSV (Open Source Vulnerabilities) database.

Designed with a modular and extensible architecture, it supports checking direct and transitive dependencies and requires **zero external python package installations**.

![Kevlar CheckDeps Dashboard](assets/dashboard.png)

---

## Key Features

- **Multi-Ecosystem Support**: Audits:
  - **Node.js (`npm`) & Engines**: supporting `package.json`, `package-lock.json`, Yarn `yarn.lock`, and pnpm `pnpm-lock.yaml`. Audits declared Node.js version constraints (`engines.node`, `.nvmrc`, `.node-version`) against EOL and maintenance schedules fetched dynamically from official sources.
  - **Python (`pip`)**: supporting `requirements.txt`, Poetry `poetry.lock` + `pyproject.toml`, Pipenv `Pipfile.lock`, and PDM `pdm.lock`.
  - **.NET (`nuget`)**: supporting C# `.csproj`, VB.NET `.vbproj`, F# `.fsproj`, Solution files (`.sln`), and Central Package Management (`Directory.Packages.props`).
  - **PHP (`php`)**: supporting `composer.json` and `composer.lock`.
  - **Java (`maven`)**: supporting multi-module `<modules>`, centralized `<dependencyManagement>`, and recursive parent POM properties/dependency inheritance.
  - **Java/Kotlin (`gradle`)**: supporting `build.gradle`, `build.gradle.kts`, `gradle.lockfile`, and Version Catalogs `libs.versions.toml`.
  - **Android (`android`)**: prioritizing Google's Maven Registry for Android libraries.
  - **Go (`go`)**: supporting `go.mod`.
  - **Rust (`rust`)**: supporting `Cargo.toml` and `Cargo.lock`.
  - **Ruby (`ruby`)**: supporting `Gemfile` and `Gemfile.lock`.
- **Outdated Package Detection**: Compares installed versions against the latest versions in registries, classifying updates into `Major`, `Minor`, and `Patch` increments.
- **Deprecation Warnings**: 
  - For `npm`: Extracts maintainer deprecation notices for exact installed versions.
  - For `pip`: Identifies and reports "yanked" (deprecated/withdrawn) releases on PyPI.
  - For `rust`: Identifies and reports "yanked" crates on crates.io.
- **Security Vulnerability Audits**: Queries the public Google OSV database to identify active vulnerabilities, including CVE/GHSA IDs, CVSS vectors, and advisory summaries.
- **Transitive Parent Tracing**:
  - For `npm`: Recursively builds a dependency graph from `package-lock.json`, Yarn `yarn.lock`, or pnpm `pnpm-lock.yaml`.
  - For `pip`: Parses transitives from lockfiles (`poetry.lock`, `Pipfile.lock`, `pdm.lock`) or `# via parent_name` comments inside `requirements.txt`.
  - For `nuget`: Reconstructs the parent-child graph from `obj/project.assets.json`.
  - For `php`: Reconstructs the parent-child graph from `composer.lock`.
  - For `go`: Flags indirect packages inside `go.mod` as transitive dependencies.
  - For `rust`: Reconstructs the parent-child graph from `Cargo.lock`.
  - For `ruby`: Reconstructs the parent-child graph from `Gemfile.lock`.
  - Annotates transitive packages clearly in reports (e.g., `Transitive (via Newtonsoft.Json)`).
- **Fast Execution**: Uses Python's `concurrent.futures.ThreadPoolExecutor` to perform network requests concurrently.
- **High Performance Scanning**: Optimizes queries by requesting abbreviated metadata format headers from npm, and checks security advisories in a single `POST /v1/querybatch` request rather than one-by-one.
- **Visual Console Reporting**: Displays findings in a neat, colorized table with summary statistics.
- **Terminal Compatibility Fallback**: Automatically detects standard terminal encoding capabilities, switching seamlessly from Unicode characters to clean ASCII frames to prevent encoding crashes on Windows consoles.
- **JSON, Markdown & HTML Exports**: Supports exporting results to formatted Markdown tables, raw JSON datasets, or interactive HTML dashboards.
- **NPM Registry Checksum Auditing**: For Node.js (`npm`), cross-validates local lockfile integrity hashes against official registry metadata, flagging **Missing Checksums**, **Weak Algorithms** (SHA-1), and critical **Integrity Mismatches**.
- **Advanced HTML Filtering Controls**: Interactive HTML dashboards include:
  - **AND Intersection Filtering**: Combine multiple filters (e.g., *Outdated* + *Vulnerable*) to show only packages matching all selected categories.
  - **Dependency Scope/Type Filtering**: Filter packages dynamically by their scope (e.g., *Direct*, *Dev*, *Transitive*, *Engine*) using the new **Scope** dropdown filter.
  - **Quick "only / all" Hover Controls**: Instantly isolate sub-filters or check all back on hover.
  - **Auto-closing & Smart Resetting**: Auto-closes menus when clicking outside and resets checkboxes when switching to *All* or *Clean*.

---

## Installation & Requirements

- **Python**: Version 3.6 or higher.
- **Zero Dependencies**: The script relies **only on Python standard libraries** (`urllib.request`, `concurrent.futures`, `json`, `argparse`, `sys`, `re`, `unicodedata`, `xml.etree.ElementTree`). No `pip install` is required!

To start, simply download/clone the workspace and run the script:
```powershell
python kevlar.py --help
```

---

## How to Use

### 1. Basic Scan (Direct dependencies only)
Kevlar automatically detects the technology footprint of your project if you omit the `--tech` option (or explicitly specify `auto`). You can also target a specific ecosystem via `--tech` (or `-t`) along with the directory via `--path` (or `-p`):

- **Automatic Technology Footprint Scan**:
  ```powershell
  python kevlar.py --path ./my_project
  ```
- **For Node.js (npm)**:
  ```powershell
  python kevlar.py --tech npm --path ./nodejs_project
  ```
- **For Python (pip)**:
  ```powershell
  python kevlar.py --tech pip --path ./python_project
  ```
- **For .NET (nuget)**:
  ```powershell
  python kevlar.py --tech nuget --path ./dotnet_project
  ```
- **For PHP (php)**:
  ```powershell
  python kevlar.py --tech php --path ./php_project
  ```
- **For Java (maven)**:
  ```powershell
  python kevlar.py --tech maven --path ./java_project
  ```
- **For Go (go)**:
  ```powershell
  python kevlar.py --tech go --path ./go_project
  ```
- **For Rust (rust)**:
  ```powershell
  python kevlar.py --tech rust --path ./rust_project
  ```
- **For Ruby (ruby)**:
  ```powershell
  python kevlar.py --tech ruby --path ./ruby_project
  ```
- **For Java/Kotlin (gradle)**:
  ```powershell
  python kevlar.py --tech gradle --path ./gradle_project
  ```
- **For Android (android)**:
  ```powershell
  python kevlar.py --tech android --path ./android_project
  ```

### 2. Scan Security Vulnerabilities
Add the `--vuls` (or `-v`) flag to audit packages against Google's OSV database:
```powershell
python kevlar.py --tech nuget --path ./dotnet_project --vuls
```

### 3. Scan All Dependencies (Direct + Transitive)
Add the `--all` (or `-a`) flag to scan the entire tree resolved in lockfiles/assets:
- **For Node.js (npm)**:
  ```powershell
  python kevlar.py --tech npm --path ./nodejs_project --all --vuls
  ```
- **For .NET (nuget)**:
  ```powershell
  python kevlar.py --tech nuget --path ./dotnet_project --all --vuls
  ```
- **For PHP (php)**:
  ```powershell
  python kevlar.py --tech php --path ./php_project --all --vuls
  ```
- **For Rust (rust)**:
  ```powershell
  python kevlar.py --tech rust --path ./rust_project --all --vuls
  ```
- **For Ruby (ruby)**:
  ```powershell
  python kevlar.py --tech ruby --path ./ruby_project --all --vuls
  ```
*(For pip, if your `requirements.txt` contains transitive comments from `pip-compile`, the script will automatically parse and display parent tracing details).*
*(For Java / Maven, if you point the path to a parent POM, the script will automatically discover and aggregate all sub-modules recursively).*

### 4. Recursive Scan of Multiple Projects (`--scan-all`)
To scan a directory recursively for multiple projects, automatically detect their technologies, and audit each of them:
- **Scan all projects recursively**:
  Add the `--scan-all` flag. When using `--scan-all`, you must also specify the report format using `--format` (choices: `html`, `json`, `both`).
  ```powershell
  python kevlar.py --scan-all --format both --path ./my_workspace
  ```
  This will scan `./my_workspace`, audit all detected projects in real-time, print progress to the console, and automatically write separate, isolated report files named after their directory path (e.g. `report-my_api.html`, `report-frontend_app.json`).
- **Filter recursive search by technology**:
  You can filter the search to scan only projects of a specific technology (e.g. `pip`) by combining `--scan-all` with `--tech`:
  ```powershell
  python kevlar.py --scan-all --tech pip --format html --path ./my_workspace
  ```

### 5. Export Report Files
Output findings into structured Markdown (`.md`), raw JSON (`.json`), or interactive HTML dashboard (`.html`) files using `--output` (or `-o`):
- **For Markdown**:
  ```powershell
  python kevlar.py --tech nuget --path ./dotnet_project --vuls --output dependency_report.md
  ```
- **For Interactive HTML**:
  ```powershell
  python kevlar.py --tech nuget --path ./dotnet_project --vuls --output dependency_report.html
  ```

### 6. Show Up-to-Date Packages
By default, the tool only shows packages that have issues (outdated, deprecated, vulnerable, or errored). Use `--show-all` to list all packages:
```powershell
python kevlar.py --tech nuget --path ./dotnet_project --show-all
```

### 7. Check for Updates
Check if a newer version of Kevlar is available on GitHub:
```powershell
python kevlar.py --update
```

---

## CLI Options Reference

| Argument | Short | Default | Description |
| --- | --- | --- | --- |
| `--tech` | `-t` | `"auto"` | The package manager / technology to check. Choices: `npm`, `pip`, `nuget`, `php`, `maven`, `go`, `rust`, `ruby`, `gradle`, `android`, `auto`. When omitted, it automatically detects the technology at the target `--path`. |
| `--path` | `-p` | `.` | Directory containing the package files (e.g. `.csproj`, `composer.json`, `package.json`, `pom.xml`, `go.mod`, `requirements.txt`, `Cargo.toml`, `Gemfile`, `build.gradle`, `libs.versions.toml`, etc.). |
| `--vuls` | `-v` | `False` | Enable security vulnerability queries via Google OSV API. |
| `--all` | `-a` | `False` | Scan all dependencies resolved in lockfile, rather than direct ones. |
| `--concurrent` | `-c` | `10` | Number of concurrent network request threads to run. |
| `--output` | `-o` | `None` | Path to export report file (detects `.json`, `.md`, and `.html` formats). Not allowed when using `--scan-all`. |
| `--show-all` | | `False` | Display all dependencies, even those up-to-date and secure. |
| `--scan-all` | | `False` | Recursively scan the path for multiple projects, automatically detecting their technologies. |
| `--format` | | `None` | Output report format when using `--scan-all`. Choices: `html`, `json`, `both`. |
| `--fail-on-vulns` | | `None` | Break the build (exit code 1) on security issues. Accepts threshold limits (e.g., `"critical:2,high:4"`). |
| `--fail-on-deprecated` | | `None` | Break the build (exit code 1) if deprecated packages are found. Optionally specify count threshold (e.g., `3`). |
| `--fail-on-outdated` | | `None` | Break the build (exit code 1) if outdated packages are found. Optionally specify count threshold (e.g., `3`) or specific status levels (e.g., `major:2,minor:4`). |
| `--suppress` | `-s` | `None` | Path to a JSON file containing vulnerability suppressions (default: look for `kevlar-suppressions.json` in the active path). |
| `--update` | | `False` | Check for updates from GitHub. |
---

## CI/CD Pipeline Integration & Build Breaking

For security auditing, you can use the `--fail-on-vulns` flag to automatically exit with status `1` (failing the pipeline build) if vulnerabilities are found.

### Build Breaking Strategies

1. **Fail on Any Vulnerability**:
   Passing the argument without values defaults to failing if there is at least one vulnerability:
   ```powershell
   python kevlar.py --tech pip --path ./project --vuls --fail-on-vulns
   ```

2. **Custom Severity Thresholds (OR Logic)**:
   Specify the exact severity limits as a comma-separated list of `severity:limit`. The build breaks if **any** limit is breached:
   - Break if there are **at least 2 critical** vulnerabilities:
     ```powershell
     python kevlar.py --tech pip --path ./project --vuls --fail-on-vulns "critical:2"
     ```
   - Break if there are **at least 2 critical OR 4 high** vulnerabilities:
     ```powershell
     python kevlar.py --tech pip --path ./project --vuls --fail-on-vulns "critical:2,high:4"
     ```

Valid severity identifiers: `critical`, `high`, `medium`, `low`, `unknown`. (CVSS vector strings are parsed dynamically to extract their scores and map to these levels: Critical $\ge 9.0$, High $\ge 7.0$, Medium $\ge 4.0$, Low $\ge 0.1$).

3. **Fail on Deprecated Dependencies**:
   - Fails if there is **at least one** deprecated package:
     ```powershell
     python kevlar.py --path ./project --fail-on-deprecated
     ```
   - Fails if there are **at least 3** deprecated packages:
     ```powershell
     python kevlar.py --path ./project --fail-on-deprecated 3
     ```

4. **Fail on Outdated Dependencies**:
   - Fails if there is **at least one** outdated package (major, minor, or patch):
     ```powershell
     python kevlar.py --path ./project --fail-on-outdated
     ```
   - Fails if there are **at least 5** outdated packages:
     ```powershell
     python kevlar.py --path ./project --fail-on-outdated 5
     ```
   - Fails based on granular **update status types** (OR logic). Break if there are **at least 1 major OR 3 minor** updates:
     ```powershell
     python kevlar.py --path ./project --fail-on-outdated "major:1,minor:3"
     ```

Valid status level identifiers: `major`, `minor`, `patch`.

### Pipeline Examples

#### 1. GitHub Actions (`.github/workflows/dependency-scan.yml`)
You can run the script and publish a JSON report as a build artifact:
```yaml
name: Dependency Vulnerability Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Run Dependency Checker
        run: |
          python kevlar.py --tech npm --path ./ --vuls --fail-on-vulns "critical:1,high:3" --output report.json

      - name: Upload Scan Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: dependency-audit-report
          path: report.json
```

#### 2. GitLab CI (`.gitlab-ci.yml`)
Run the scanner in a Python environment, export the JSON report, and upload it as a job artifact:
```yaml
stages:
  - test

dependency_scan:
  stage: test
  image: python:3.10-slim
  script:
    # Run audit, failing if there is at least 1 critical or 3 high vulnerabilities
    - python kevlar.py --tech nuget --path ./ --all --vuls --fail-on-vulns "critical:1,high:3" --output report.json
  artifacts:
    name: "dependency-audit-report"
    expose_as: "Dependency Audit Report"
    when: always
    paths:
      - report.json
```

---

## Vulnerability Suppression (Ignoring Alerts)

You can suppress specific vulnerability alerts to prevent them from breaking your build pipelines. Create a JSON file (by default `kevlar-suppressions.json` in the project directory) containing your rules:

```json
{
  "suppressions": [
    {
      "id": "GHSA-pq67-6m6q-mj2v",
      "reason": "Redirecciones no deshabilitadas en PoolManager mitigadas en nuestro código."
    },
    {
      "package": "certifi",
      "reason": "Librería de certifi utilizada únicamente en entorno local/testeo."
    },
    {
      "package": "django",
      "id": "GHSA-2gwj-7jmv-h26r",
      "reason": "Inyección SQL mitigada por nuestro uso del ORM nativo seguro."
    }
  ]
}
```

Rules support:
- Suppressing by Vulnerability ID (CVE or GHSA) globally across all packages.
- Suppressing an entire package's vulnerabilities.
- Suppressing a specific vulnerability ID on a specific package.

---

## Design Considerations & Behavior

### 1. Performance Optimizations
- **Concurrency**: Registry queries for package metadata are executed concurrently using Python's `concurrent.futures.ThreadPoolExecutor`. By default, it runs with `10` threads, which can be tuned using `--concurrent`.
- **Abbreviated npm Metadata**: Queries to the npm registry request abbreviated package metadata format (`application/vnd.npm.install-v1+json`), reducing HTTP response payload size by over 95%.
- **Vulnerability Query Batching**: Queries to the Google OSV API are executed in single large POST batches (`/v1/querybatch`) up to 1000 packages per request, preventing multiple slow individual API roundtrips.
- **Configurable Endpoints**: All external registry and vulnerability API endpoints are defined as configuration variables at the top of [kevlar.py](kevlar.py) for easy customization.

### 2. Version Comparison Logic
To correctly flag outdated packages, the tool runs a custom Semantic Versioning parser that supports:
- Up to 4 version segment digits (e.g. `1.2.3.4`).
- Classification of updates into `Major` (breaking changes), `Minor` (new backward-compatible features), and `Patch` (bug fixes).
- Auto-ignoring pre-release version metadata during update classifications.
- Exact mapping of C# and VB.NET central package dependencies when CPM version tags are inherited.
