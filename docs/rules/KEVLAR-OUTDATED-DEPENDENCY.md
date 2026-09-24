---
id: KEVLAR-OUTDATED-DEPENDENCY
title: "Outdated Dependency"
level: warning
precision: very-high
tags:
  - dependency
  - outdated
  - maintenance
  - sca
  - technical-debt
helpUri: "https://kevlar-checkdeps.dev/rules/KEVLAR-OUTDATED-DEPENDENCY"
---

# KEVLAR-OUTDATED-DEPENDENCY: Outdated Dependency

## 1. Executive Overview

The **`KEVLAR-OUTDATED-DEPENDENCY`** rule identifies third-party software components (libraries, frameworks, and modules) whose installed or resolved version lags behind the latest stable release published in the corresponding official package registry (npm, PyPI, NuGet, Packagist, or Go Proxy).

This rule triggers during Software Composition Analysis (SCA) when Kevlar detects that:
1. A newer upstream release exists compared to the version installed locally or pinned in the project lockfile.
2. The available upgrade corresponds to a SemVer 2.0.0 increment of type:
   - **Patch (`x.y.Z`)**: Bug fixes and minor security patches.
   - **Minor (`x.Y.z`)**: Backwards-compatible new features.
   - **Major (`X.y.z`)**: Architectural changes and breaking changes.

> [!NOTE]
> Even if an outdated dependency does not currently map to a formally assigned CVE or GHSA identifier, sustained delay in upgrading third-party packages represents one of the largest indirect attack vectors in modern software supply chains.

---

## 2. Technical & Security Impact

Keeping outdated dependencies over time introduces critical operational and security risks:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      SECURITY DEGRADATION CYCLE                        │
│                                                                        │
│   Legacy Version ──► Silent Fixes ──────► Accumulated Breaking Changes │
│         │                  │                              │            │
│         ▼                  ▼                              ▼            │
│    No security       1-Day vulnerabilities      High-friction emergency│
│      support          exposed to attackers        migration in crisis  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1. Latent Vulnerabilities and "Silent Security Fixes"
Approximately **60% of open-source security patches are not immediately accompanied by a public CVE advisory**. Instead, maintainers often merge them as routine bug fixes or refactors in minor or patch releases. Attackers routinely perform automated patch diffing on public commit histories to identify exploitable flaws in older versions still deployed across production systems.

### 2.2. Technical Debt and "Upgrade Paralysis"
As dependencies fall multiple major versions behind, the effort and friction required to upgrade compound exponentially. Incompatible API changes, deprecated interfaces, and cascading dependency conflicts prevent engineering teams from quickly applying security patches during zero-day incidents without risking application outages.

### 2.3. Platform and Runtime Incompatibility
Outdated libraries eventually drop support for modern runtimes (such as active Node.js LTS, current Python releases, modern .NET CLR, or supported PHP engines). This forces organizations to retain end-of-life runtimes that themselves harbor unpatched operating system and engine-level vulnerabilities.

| SemVer Increment | SARIF Severity | Operational Impact | Security Risk |
| :--- | :--- | :--- | :--- |
| **Major (`X.0.0`)** | `error` | High (Breaking changes expected) | Critical: Legacy release line abandonment |
| **Minor (`0.Y.0`)** | `warning` | Medium (New APIs, low breaking risk) | High: Latent functional and security fixes |
| **Patch (`0.0.Z`)** | `note` | Low (Stability fixes) | Moderate: Direct bug patches |

---

## 3. Detection Logic and SARIF Metadata

Kevlar inspects direct and transitive dependencies from project manifests (`package.json`, `requirements.txt`, `.csproj`, `composer.json`, `go.mod`) and lockfiles. It subsequently queries official upstream registry APIs for the latest release tagged as `latest` or `stable` (filtering out alpha, beta, and release candidates unless explicitly configured).

### SARIF v2.1.0 Metadata Structure (`properties`)
When Kevlar emits findings, it links them to `KEVLAR-OUTDATED-DEPENDENCY` and populates the `properties` bag with granular telemetry:

```json
{
  "ruleId": "KEVLAR-OUTDATED-DEPENDENCY",
  "ruleIndex": 1,
  "level": "warning",
  "message": {
    "text": "Outdated dependency: package 'axios' (version 0.27.2) is behind latest version '1.7.2' (major update available)."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "package.json",
          "uriBaseId": "%SRCROOT%"
        },
        "region": {
          "startLine": 18,
          "startColumn": 1
        }
      }
    }
  ],
  "properties": {
    "packageName": "axios",
    "installedVersion": "0.27.2",
    "latestVersion": "1.7.2",
    "declaredConstraint": "^0.27.2",
    "technology": "npm",
    "updateType": "major"
  }
}
```

* **`packageName`**: Canonical package name within the ecosystem.
* **`installedVersion`**: Exact version resolved and identified in the environment or lockfile.
* **`latestVersion`**: Most recent stable version available upstream.
* **`declaredConstraint`**: Range or requirement specifier defined in the source manifest.
* **`updateType`**: SemVer classification of the version delta (`major`, `minor`, or `patch`).

---

## 4. Step-by-Step Remediation Guide (Per Ecosystem)

### 4.1. Node.js / npm

1. **Inspect outdated dependencies:**
   ```bash
   npm outdated
   ```

2. **Update within permitted SemVer range (Minor/Patch):**
   ```bash
   npm update axios
   ```

3. **Upgrade across Major breaking changes:**
   ```bash
   npm install axios@latest
   ```

4. **Manual edit in `package.json`:**
   ```diff
    "dependencies": {
   -  "axios": "^0.27.2"
   +  "axios": "^1.7.2"
    }
   ```
   > [!IMPORTANT]
   > After modifying `package.json`, run `npm install` to update `package-lock.json` deterministically, followed by your automated test suite.

---

### 4.2. Python / pip

1. **Standard `pip` and `requirements.txt` workflows:**
   ```bash
   # List outdated packages
   pip list --outdated

   # Upgrade package in current virtual environment
   pip install --upgrade requests
   ```
   *Edit `requirements.txt`:*
   ```diff
   -requests==2.28.1
   +requests==2.32.3
   ```

2. **Workflows using `pip-tools`:**
   ```bash
   # Upgrade within requirements.in and recompile
   pip-compile --upgrade-package requests requirements.in
   pip-sync requirements.txt
   ```

3. **Workflows using Poetry:**
   ```bash
   poetry show --outdated
   poetry update requests
   ```

---

### 4.3. .NET / NuGet

1. **Inspect via .NET CLI:**
   ```bash
   dotnet list package --outdated
   ```

2. **Upgrade package:**
   ```bash
   dotnet add package Newtonsoft.Json --version 13.0.3
   ```

3. **Direct edit in `.csproj` or `Directory.Packages.props` (Central Package Management):**
   ```diff
    <ItemGroup>
   -  <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
   +  <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    </ItemGroup>
   ```

4. **Restore dependencies:**
   ```bash
   dotnet restore
   ```

---

### 4.4. PHP / Composer

1. **Inspect outdated packages:**
   ```bash
   composer outdated
   ```

2. **Update package and required dependency sub-trees:**
   ```bash
   composer update guzzlehttp/guzzle --with-dependencies
   ```

3. **Direct edit in `composer.json`:**
   ```diff
    "require": {
   -  "guzzlehttp/guzzle": "^7.4.0"
   +  "guzzlehttp/guzzle": "^7.8.1"
    }
   ```

---

### 4.5. Go

1. **List outdated modules:**
   ```bash
   go list -u -m all
   ```

2. **Upgrade to latest stable minor/patch or targeted version:**
   ```bash
   go get -u github.com/gin-gonic/gin@v1.10.0
   ```

3. **Clean up and synchronize `go.sum`:**
   ```bash
   go mod tidy
   ```

---

## 5. Automated SARIF Remediation (`fixes`)

Kevlar features an integrated `SarifFixBuilder` engine that emits a compliant `fixes` block according to **OASIS SARIF v2.1.0 §3.55**. Compatible platforms (such as GitHub Code Scanning, GitLab CI, and the VS Code SARIF Viewer extension) can apply manifest changes with a single click.

### Example SARIF `fixes` Payload Emitted by Kevlar

```json
"fixes": [
  {
    "description": {
      "text": "Remediate dependency update for package 'axios'"
    },
    "artifactChanges": [
      {
        "artifactLocation": {
          "uri": "package.json",
          "uriBaseId": "%SRCROOT%"
        },
        "replacements": [
          {
            "deletedRegion": {
              "startLine": 18,
              "startColumn": 1,
              "endLine": 18
            },
            "insertedContent": {
              "text": "    \"axios\": \"^1.7.2\",\n"
            }
          }
        ]
      }
    ]
  }
]
```

* **`artifactLocation.uri`**: Relative repository path anchored to `%SRCROOT%`, stripped of directory traversal sequences (`../`).
* **`deletedRegion`**: Exact coordinates of the target manifest line declaring the outdated dependency.
* **`insertedContent.text`**: Preserved indentation and syntax with the updated version constraint.

---

## 6. Governance and Suppressions (`kevlar-suppressions.json`)

When an upcoming major version upgrade requires substantial architectural refactoring scheduled for a future sprint, teams can suppress the finding using `kevlar-suppressions.json`.

> [!WARNING]
> Suppressions lacking expiration dates or containing generic justifications violate secure software supply chain governance. All policy exceptions must be reviewed and signed off by a designated Security Champion or AppSec Officer.

### Example Justified Suppression

```json
{
  "$schema": "./kevlar-suppressions.schema.json",
  "metadata": {
    "version": "1.0.0",
    "last_modified": "2026-09-24",
    "approved_by": "AppSec Security Office"
  },
  "suppressions": [
    {
      "id": "KEVLAR-OUTDATED-DEPENDENCY",
      "package": "axios",
      "ecosystem": "npm",
      "reason": "ACCEPTED_TEMPORARY_RISK",
      "justification": "Upgrade to axios v1.x introduces breaking changes in custom HTTP interceptors. Migration scheduled and assigned in Jira ticket SEC-4091 for Q4 sprint.",
      "expires_at": "2026-11-30",
      "created_by": "Developer Charlie",
      "approved_by": "AppSec Officer Bob"
    }
  ]
}
```

### Required Fields for Suppression Policy:
* **`id`**: Must match `KEVLAR-OUTDATED-DEPENDENCY` (or `*` to match all checks on the package).
* **`package`**: Exact package identifier (case-insensitive evaluation).
* **`reason`**: Approved risk classification enum (`ACCEPTED_TEMPORARY_RISK`, `COMPENSATING_CONTROL_IMPLEMENTED`).
* **`justification`**: Technical rationale explaining why the risk is safely deferred (minimum 15 characters).
* **`expires_at`**: Strict expiration date formatted as ISO 8601 (`YYYY-MM-DD`). Once expired, Kevlar will fail CI/CD builds.
* **`approved_by`**: Identity of the security officer who validated the risk.

---

## 7. References and Standards

* **Semantic Versioning 2.0.0**: [https://semver.org/spec/v2.0.0.html](https://semver.org/spec/v2.0.0.html)
* **OASIS SARIF v2.1.0 Standard**: [https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
* **OpenSSF Best Practices Working Group**: [https://bestpractices.coreinfrastructure.org/](https://bestpractices.coreinfrastructure.org/)
* **NIST SP 800-218: Secure Software Development Framework (SSDF)**: Requirements PW.4 and RV.1 on recurring dependency upgrades.
* **Kevlar Documentation Portal**: [https://kevlar-checkdeps.dev/rules/KEVLAR-OUTDATED-DEPENDENCY](https://kevlar-checkdeps.dev/rules/KEVLAR-OUTDATED-DEPENDENCY)
