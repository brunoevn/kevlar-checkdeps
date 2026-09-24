---
id: KEVLAR-CONFIG-DRIFT
title: "Dependency Configuration Drift"
level: error
precision: very-high
tags:
  - configuration
  - drift
  - sca
  - integrity
  - deterministic-builds
helpUri: "https://kevlar-checkdeps.dev/rules/KEVLAR-CONFIG-DRIFT"
---

# KEVLAR-CONFIG-DRIFT: Dependency Configuration Drift

## 1. Executive Overview

The **`KEVLAR-CONFIG-DRIFT`** rule identifies critical discrepancies between the version constraint declared in project manifests (`package.json`, `requirements.txt`, `.csproj`, `composer.json`, `go.mod`) and the actual package version resolved and installed in the local environment, container image, or lockfile.

This rule triggers with **`error`** severity when Kevlar validates that:
$$\text{Installed Version} \notin \text{Declared Constraint Range}$$

A classic scenario involves a manifest demanding `urllib3>=2.0.0` while the execution environment or base image retains `1.26.15`, or when `package.json` specifies `lodash: "^4.17.21"` but `node_modules` hosts `3.10.1`.

> [!CAUTION]
> Configuration drift breaks the immutability of build artifacts and invalidates regression testing conducted during development and CI cycles.

---

## 2. Technical & Security Impact

Discrepancies between developer intent (manifest) and runtime reality (lockfile / environment) introduce severe process and security liabilities:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      CONFIGURATION DRIFT RISK                          │
│                                                                        │
│   Manifest (Intent)           vs.      Lockfile / Environment (Reality)│
│   [ "lib": "^2.0.0" ]                  [ lib@1.8.4 installed ]         │
│            │                                      │                    │
│            ▼                                      ▼                    │
│   CI/CD SCA analysis                      1-Day vulnerability          │
│   assumes patched version (2.x)           running in Production        │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1. "Works on My Machine, Fails in CI/CD"
When developers install packages using unpinned or interactive commands without updating project manifests, or when lockfiles are not kept in lockstep, deployments break when promoted across staging and production. A continuous integration pipeline provisioning from a clean slate will resolve packages differently from the developer's workstation.

### 2.2. Non-Deterministic Builds
Reproducibility is a foundational pillar of software supply chain integrity. If two builds from the identical Git commit yield binaries or container images with divergent dependency trees, certifying code provenance (e.g., SLSA Framework Level 3+) becomes impossible.

### 2.3. SCA Audit Bypass and Security False Negatives
Many standard SCA scanners only inspect static manifests. If a manifest specifies a patched version, but the deployment artifact executes a vulnerable older release due to stale caches or unsynchronized lockfiles, **security dashboards will falsely indicate a compliant posture**, leaving known vulnerabilities actively exposed in production.

| Drift Type | Manifest (`Declared`) | Environment / Lockfile (`Installed`) | Operational & Security Risk |
| :--- | :--- | :--- | :--- |
| **Minor Divergence** | `>= 1.5.0` | `1.4.2` | Resolved bugs remain active in execution runtime |
| **Major Divergence** | `^2.0.0` | `1.9.0` | Incompatible security mechanisms, deprecated crypto |
| **Missing Lockfile** | Open ranges (`*`, `^`) | Unpinned | Susceptible to *Dependency Confusion* and version hijacking |

---

## 3. Detection Logic and SARIF Metadata

Kevlar implements an algebraic resolution engine supporting SemVer 2.0.0, PEP 440, Composer, and NuGet version ranges. The engine performs bidirectional cross-validation:
1. Parses declared constraints from the primary project manifest.
2. Inspects canonical lockfiles (`package-lock.json`, `poetry.lock`, `packages.lock.json`, `composer.lock`, `go.sum`) or queries the active execution runtime.
3. Formally calculates whether the resolved version falls within the declared bounds.

### SARIF v2.1.0 Metadata Structure (`properties`)
When Kevlar identifies drift, it reports an issue under `KEVLAR-CONFIG-DRIFT` with level `error`:

```json
{
  "ruleId": "KEVLAR-CONFIG-DRIFT",
  "ruleIndex": 0,
  "level": "error",
  "message": {
    "text": "Configuration Drift: Package 'urllib3' installed version (1.26.15) does not satisfy declared constraint (>=2.0.0)."
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "requirements.txt",
          "uriBaseId": "%SRCROOT%"
        },
        "region": {
          "startLine": 12,
          "startColumn": 1
        }
      }
    }
  ],
  "properties": {
    "packageName": "urllib3",
    "installedVersion": "1.26.15",
    "declaredConstraint": ">=2.0.0",
    "technology": "pip"
  }
}
```

* **`packageName`**: Name of the drifted component.
* **`installedVersion`**: Version discovered in the local runtime or lockfile.
* **`declaredConstraint`**: Constraint explicitly stated in the source manifest.
* **`technology`**: Targeted ecosystem (`npm`, `pip`, `nuget`, `php`, `go`).

---

## 4. Step-by-Step Remediation Guide (Per Ecosystem)

To remediate configuration drift, teams must either synchronize the installed version with the declared manifest or adjust the manifest constraint if the installed version is intentionally desired.

### 4.1. Node.js / npm

1. **Diagnose installed dependency path:**
   ```bash
   npm ls lodash
   ```

2. **Strictly synchronize against lockfile (Recommended for CI/CD):**
   ```bash
   # Removes node_modules and installs strictly from package-lock.json
   npm ci
   ```

3. **Reconcile lockfile to match updated manifest:**
   ```bash
   npm install lodash@^4.17.21
   ```

4. **Correct `package.json` manually:**
   ```diff
    "dependencies": {
   -  "lodash": "^3.10.1"
   +  "lodash": "^4.17.21"
    }
   ```

---

### 4.2. Python / pip

1. **Synchronize via `pip-tools`:**
   ```bash
   # Recompile lock requirements and sync environment
   pip-compile requirements.in
   pip-sync requirements.txt
   ```

2. **Synchronize via Poetry:**
   ```bash
   # Enforce strict parity with poetry.lock
   poetry install --sync
   ```

3. **Align `requirements.txt`:**
   ```diff
   -urllib3<2.0.0
   +urllib3>=2.0.0
   ```
   ```bash
   pip install -r requirements.txt --upgrade
   ```

---

### 4.3. .NET / NuGet

1. **Enforce locked mode during restores:**
   ```bash
   dotnet restore --locked-mode
   ```

2. **Align package version:**
   ```bash
   dotnet add package Microsoft.Extensions.Logging --version 8.0.0
   ```

3. **Direct edit in `.csproj`:**
   ```diff
    <ItemGroup>
   -  <PackageReference Include="Microsoft.Extensions.Logging" Version="6.0.0" />
   +  <PackageReference Include="Microsoft.Extensions.Logging" Version="8.0.0" />
    </ItemGroup>
   ```

---

### 4.4. PHP / Composer

1. **Install strictly from lockfile:**
   ```bash
   composer install
   ```

2. **Update lockfile to reflect manifest modifications:**
   ```bash
   composer update symfony/console --with-dependencies
   ```

3. **Align in `composer.json`:**
   ```diff
    "require": {
   -  "symfony/console": "^5.4"
   +  "symfony/console": "^6.4"
    }
   ```

---

### 4.5. Go

1. **Verify module integrity:**
   ```bash
   go mod verify
   ```

2. **Reconcile dependencies and clean modules:**
   ```bash
   go get golang.org/x/crypto@v0.24.0
   go mod tidy
   ```

---

## 5. Automated SARIF Remediation (`fixes`)

Kevlar can generate automated patch descriptors conforming to **OASIS SARIF v2.1.0 §3.55** to reconcile manifests directly with verified runtime versions.

### Example SARIF Fix Emitted by Kevlar

```json
"fixes": [
  {
    "description": {
      "text": "Remediate dependency update for package 'urllib3'"
    },
    "artifactChanges": [
      {
        "artifactLocation": {
          "uri": "requirements.txt",
          "uriBaseId": "%SRCROOT%"
        },
        "replacements": [
          {
            "deletedRegion": {
              "startLine": 12,
              "startColumn": 1,
              "endLine": 12
            },
            "insertedContent": {
              "text": "urllib3>=2.2.2\n"
            }
          }
        ]
      }
    ]
  }
]
```

When evaluated in a compatible IDE or CI integration, this fix replaces the inconsistent manifest line cleanly without perturbing adjacent dependencies or inline documentation.

---

## 6. Governance and Suppressions (`kevlar-suppressions.json`)

Under exceptional circumstances (such as legacy runtime backports in specialized enterprise OS distributions), configuration drift can be granted a temporary policy exception.

> [!WARNING]
> Suppressing `KEVLAR-CONFIG-DRIFT` requires formal sign-off from Lead Software Architects or Application Security Officers, as it masks configuration discrepancies capable of causing silent runtime regressions.

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
      "id": "KEVLAR-CONFIG-DRIFT",
      "package": "urllib3",
      "ecosystem": "pip",
      "reason": "VULNERABILITY_MITIGATED_BY_ENVIRONMENT",
      "justification": "Base Docker image Alpine provides system-patched urllib3 1.26.15-r2 backporting security patches. Manifest declared constraint will be harmonized in release 3.4.0.",
      "expires_at": "2026-10-31",
      "created_by": "DevOps Engineer Elena",
      "approved_by": "AppSec Officer Bob"
    }
  ]
}
```

---

## 7. References and Standards

* **Reproducible Builds Specification**: [https://reproducible-builds.org/](https://reproducible-builds.org/)
* **Supply-chain Levels for Software Artifacts (SLSA v1.0)**: [https://slsa.dev/spec/v1.0/](https://slsa.dev/spec/v1.0/)
* **OpenSSF Scorecard - Frozen Dependencies**: [https://github.com/ossf/scorecard](https://github.com/ossf/scorecard)
* **OASIS SARIF v2.1.0 Standard**: [https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
* **Kevlar Documentation Portal**: [https://kevlar-checkdeps.dev/rules/KEVLAR-CONFIG-DRIFT](https://kevlar-checkdeps.dev/rules/KEVLAR-CONFIG-DRIFT)
