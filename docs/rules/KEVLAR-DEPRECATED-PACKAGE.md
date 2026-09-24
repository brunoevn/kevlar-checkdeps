---
id: KEVLAR-DEPRECATED-PACKAGE
title: "Deprecated Package"
level: warning
precision: very-high
tags:
  - dependency
  - deprecated
  - maintenance
  - sca
  - supply-chain
helpUri: "https://kevlar-checkdeps.dev/rules/KEVLAR-DEPRECATED-PACKAGE"
---

# KEVLAR-DEPRECATED-PACKAGE: Deprecated Package

## 1. Executive Overview

The **`KEVLAR-DEPRECATED-PACKAGE`** rule detects third-party software components and libraries that have been formally designated as **deprecated, discontinued, or abandoned** by their original authors or by package registry authorities (npm, PyPI, NuGet, Packagist, or Go Modules).

This rule triggers during Software Composition Analysis when Kevlar discovers upstream registry metadata indicating:
1. An active deprecation notice (e.g., the `deprecated` attribute in npm package manifests).
2. Abandonment flags or explicit pointer to successor libraries (e.g., the `abandoned` property on Packagist or `PackageDeprecation` entries in the NuGet v3 catalog).
3. End-of-Life (EOL) notices or module-level deprecation comments (e.g., the `// Deprecated:` directive in Go module declarations).

> [!WARNING]
> Deprecated packages cease to receive security patches for newly discovered vulnerabilities. Retaining unmaintained libraries in dependency trees introduces severe, permanent exposure to software supply chain attacks.

---

## 2. Technical & Security Impact

Relying on discontinued dependencies exposes organizations to high-impact software supply chain attack vectors:

```
┌────────────────────────────────────────────────────────────────────────┐
│                 ATTACK VECTORS IN DEPRECATED PACKAGES                  │
│                                                                        │
│   Abandoned Package ──► Zero Security Patches ──► Account / Domain     │
│           │                       │               Hijacking            │
│           ▼                       ▼                       │            │
│    Incompatibility with    Unpatched forever              ▼            │
│      modern runtimes       (Perpetual 0-Day)       Malware Injection / │
│                                                    Backdoor Insertion  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1. Orphaned Libraries (*Abandonware*) and Zero Security Response
Once maintainers mark a package as deprecated, active stewardship ends. Any newly identified security flaw (Remote Code Execution, SQL Injection, SSRF, or Prototype Pollution) will remain unaddressed indefinitely (*perpetual zero-day*).

### 2.2. Account Hijacking and Software Supply Chain Takeover
Unmaintained packages registered across public registries represent prime targets for adversaries:
* **Domain Expiration Hijacking:** Attackers monitor and acquire expired domain names associated with legacy maintainer email accounts, enabling password resets on npm or PyPI.
* **Social Engineering & Maintainer Transfer:** Cybercriminals volunteer to "maintain" abandoned libraries boasting millions of downloads, subsequently injecting malicious payloads (cryptominers, environment secret harvesters, CI/CD pipeline exfiltrators).
* **Dependency Hijacking:** In registries without orphaned namespace reservation policies, package deletions permit malicious actors to re-register the exact package name.

### 2.3. Roadblock to Architectural Modernization
Discontinued components frequently lock dependency sub-trees to legacy runtime versions, preventing adoption of modern security features, performance improvements, and regulatory compliance standards (PCI-DSS 4.0, SOC 2, HIPAA).

| Risk Criterion | Actively Maintained Package | Deprecated / Abandoned Package |
| :--- | :--- | :--- |
| **Vulnerability Response Time** | Days / Weeks | None (No official remediation) |
| **Dependency Maintenance** | Continuous | Halted |
| **Hijacking Risk** | Mitigated by 2FA / MFA enforcement | High (Dormant accounts / Expired domains) |
| **Runtime Compatibility** | Preserved | Progressive breakdown |

---

## 3. Detection Logic and SARIF Metadata

Kevlar inspects official package registry metadata endpoints for authoritative deprecation markers:

* **npm:** The `deprecated` field in JSON payloads returned by `registry.npmjs.org/<package>`.
* **PyPI:** The `Development Status :: 7 - Inactive` classifier or explicit deprecation advisories in `pypi.org/pypi/<package>/json`.
* **NuGet:** Metadata in the `PackageDeprecation` catalog from the NuGet v3 API including reasons (`Legacy`, `CriticalBugs`, `Other`).
* **Packagist (PHP):** The boolean `abandoned` attribute or replacement package pointer (`"abandoned": "monolog/monolog"`).
* **Go Modules:** Standard comment directives `// Deprecated: use package X instead` in `doc.go` or module headers.

### SARIF v2.1.0 Metadata Structure (`properties`)
When an unmaintained package is identified, Kevlar registers a finding under `KEVLAR-DEPRECATED-PACKAGE`:

```json
{
  "ruleId": "KEVLAR-DEPRECATED-PACKAGE",
  "ruleIndex": 2,
  "level": "warning",
  "message": {
    "text": "Deprecated package 'request': request has been deprecated, see https://github.com/request/request/issues/3142"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "package.json",
          "uriBaseId": "%SRCROOT%"
        },
        "region": {
          "startLine": 24,
          "startColumn": 1
        }
      }
    }
  ],
  "properties": {
    "packageName": "request",
    "installedVersion": "2.88.2",
    "technology": "npm"
  }
}
```

* **`packageName`**: Name of the deprecated package.
* **`installedVersion`**: Version discovered in the project dependency tree.
* **`technology`**: Affected package ecosystem.
* **`message.text`**: Advisory message from the upstream maintainer, frequently providing the recommended successor package.

---

## 4. Step-by-Step Remediation Guide (Per Ecosystem)

Remediating a deprecated package requires **migrating to a maintained, actively supported alternative**.

### 4.1. Node.js / npm

*Example: Migrating from `request` to `axios` or native `fetch`.*

1. **Remove deprecated package:**
   ```bash
   npm uninstall request
   ```

2. **Install supported replacement:**
   ```bash
   npm install axios
   ```

3. **Update `package.json`:**
   ```diff
    "dependencies": {
   -  "request": "^2.88.2"
   +  "axios": "^1.7.2"
    }
   ```

---

### 4.2. Python / pip

*Example: Migrating from abandoned crypto library `pycrypto` to `cryptography`.*

1. **Uninstall legacy package:**
   ```bash
   pip uninstall pycrypto
   ```

2. **Install maintained library:**
   ```bash
   pip install cryptography
   ```

3. **Update `requirements.txt`:**
   ```diff
   -pycrypto==2.6.1
   +cryptography==42.0.8
   ```

---

### 4.3. .NET / NuGet

*Example: Migrating from `Microsoft.Azure.DocumentDB` to `Microsoft.Azure.Cosmos`.*

1. **Remove deprecated package:**
   ```bash
   dotnet remove package Microsoft.Azure.DocumentDB
   ```

2. **Install successor package:**
   ```bash
   dotnet add package Microsoft.Azure.Cosmos --version 3.40.0
   ```

3. **Direct edit in `.csproj`:**
   ```diff
    <ItemGroup>
   -  <PackageReference Include="Microsoft.Azure.DocumentDB" Version="2.18.0" />
   +  <PackageReference Include="Microsoft.Azure.Cosmos" Version="3.40.0" />
    </ItemGroup>
   ```

---

### 4.4. PHP / Composer

*Example: Migrating from `zendframework/zend-diactoros` to `laminas/laminas-diactoros`.*

1. **Remove abandoned package:**
   ```bash
   composer remove zendframework/zend-diactoros
   ```

2. **Require supported replacement:**
   ```bash
   composer require laminas/laminas-diactoros
   ```

3. **Edit in `composer.json`:**
   ```diff
    "require": {
   -  "zendframework/zend-diactoros": "^2.2"
   +  "laminas/laminas-diactoros": "^3.3"
    }
   ```

---

### 4.5. Go

*Example: Migrating deprecated packages to new module import paths.*

1. **Refactor imports in `.go` source files:**
   Replace the deprecated import path with the new module path across application code.

2. **Fetch new module and tidy dependencies:**
   ```bash
   go get github.com/golang-jwt/jwt/v5@v5.2.1
   go mod tidy
   ```

3. **Verify in `go.mod`:**
   ```diff
    module myapp

    go 1.22

    require (
   -  github.com/dgrijalva/jwt-go v3.2.0+incompatible
   +  github.com/golang-jwt/jwt/v5 v5.2.1
    )
   ```

---

## 5. Automated SARIF Remediation (`fixes`)

In scenarios where 1:1 drop-in forks or direct package renames exist (such as the Zend Framework to Laminas Project transition), Kevlar emits a `fixes` descriptor conforming to **OASIS SARIF v2.1.0 §3.55**.

### Example SARIF Fix Emitted by Kevlar

```json
"fixes": [
  {
    "description": {
      "text": "Migrate deprecated package 'zendframework/zend-diactoros' to 'laminas/laminas-diactoros'"
    },
    "artifactChanges": [
      {
        "artifactLocation": {
          "uri": "composer.json",
          "uriBaseId": "%SRCROOT%"
        },
        "replacements": [
          {
            "deletedRegion": {
              "startLine": 16,
              "startColumn": 1,
              "endLine": 16
            },
            "insertedContent": {
              "text": "        \"laminas/laminas-diactoros\": \"^3.3.0\",\n"
            }
          }
        ]
      }
    ]
  }
]
```

---

## 6. Governance and Suppressions (`kevlar-suppressions.json`)

Because migrating away from deprecated libraries frequently entails codebase refactoring, engineering teams may grant temporary policy waivers tracked in internal ticket backlogs.

> [!CAUTION]
> A suppression for `KEVLAR-DEPRECATED-PACKAGE` must never be permanent. Waivers should span a maximum of 90 to 180 days with required periodic reviews by the security team.

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
      "id": "KEVLAR-DEPRECATED-PACKAGE",
      "package": "request",
      "ecosystem": "npm",
      "reason": "ACCEPTED_TEMPORARY_RISK",
      "justification": "Deprecated 'request' library is encapsulated inside a legacy payment gateway adapter. Full migration to native fetch is tracked under architectural epic ARCH-882 scheduled for completion before Q1.",
      "expires_at": "2026-12-15",
      "created_by": "Senior Architect Carlos",
      "approved_by": "AppSec Officer Bob"
    }
  ]
}
```

---

## 7. References and Standards

* **OpenSSF Best Practices - Maintained Software**: [https://bestpractices.coreinfrastructure.org/](https://bestpractices.coreinfrastructure.org/)
* **CISA - Open Source Software Security Roadmap**: [https://www.cisa.gov/resources-tools/resources/open-source-software-security-roadmap](https://www.cisa.gov/resources-tools/resources/open-source-software-security-roadmap)
* **npm Documentation on Deprecating Packages**: [https://docs.npmjs.com/deprecating-and-undeprecating-packages-or-package-versions](https://docs.npmjs.com/deprecating-and-undeprecating-packages-or-package-versions)
* **OASIS SARIF v2.1.0 Standard**: [https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
* **Kevlar Documentation Portal**: [https://kevlar-checkdeps.dev/rules/KEVLAR-DEPRECATED-PACKAGE](https://kevlar-checkdeps.dev/rules/KEVLAR-DEPRECATED-PACKAGE)
