## 2024-05-18 - XSS vulnerability in HTML report JSON injection
**Vulnerability:** XSS vulnerability in `kevlar.py` where `UNIQUE_PROJECT_PATHS` and `UNIQUE_TECHNOLOGIES` were injected into the HTML report template inside a `<script>` tag without HTML/JSON string escaping. An attacker could name a project directory `</script><script>alert("XSS")</script>` and execute arbitrary JS when the report is viewed.
**Learning:** Just because a value is JSON dumped does not make it safe for HTML `<script>` tags, because the sequence `</script>` can break out of the tag.
**Prevention:** Always apply HTML-safe encoding (e.g. `.replace("<", "\u003c")`) to JSON data embedded directly inside HTML script tags.
