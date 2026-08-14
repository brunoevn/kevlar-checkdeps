## 2024-05-18 - Prevent Path Traversal in Requirements Parsing
**Vulnerability:** Path traversal possible when resolving included files in `requirements.txt` (`-r` or `-c`).
**Learning:** Arbitrary paths could be injected because `os.path.abspath(os.path.join(..., inc_target))` allowed traversing up out of the project base directory when evaluating recursive inclusions.
**Prevention:** Use the `_is_safe_path` helper function to validate that resolved paths never escape the base project directory before proceeding to read and parse the file.

## 2024-05-18 - XSS vulnerability in HTML report JSON injection
**Vulnerability:** XSS vulnerability in `kevlar.py` where `UNIQUE_PROJECT_PATHS` and `UNIQUE_TECHNOLOGIES` were injected into the HTML report template inside a `<script>` tag without HTML/JSON string escaping. An attacker could name a project directory `</script><script>alert("XSS")</script>` and execute arbitrary JS when the report is viewed.
**Learning:** Just because a value is JSON dumped does not make it safe for HTML `<script>` tags, because the sequence `</script>` can break out of the tag.
**Prevention:** Always apply HTML-safe encoding (e.g. `.replace("<", "\u003c")`) to JSON data embedded directly inside HTML script tags.


## 2025-02-23 - Prevent XXE vulnerability in solution file parsing
**Vulnerability:** XML External Entity (XXE) injection was possible when parsing `.slnx` solution files using standard `xml.etree.ElementTree.parse`.
**Learning:** Even internal helper scripts that parse XML solution files can be targeted if malicious project files are submitted.
**Prevention:** Always use custom secure parsing functions like `safe_et_parse` defined in the Kevlar codebase instead of standard `xml.etree.ElementTree` parsing methods (`ET.parse`) to prevent XML External Entity (XXE) vulnerabilities.
