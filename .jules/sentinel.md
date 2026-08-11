## 2024-05-18 - Prevent Path Traversal in Requirements Parsing
**Vulnerability:** Path traversal possible when resolving included files in `requirements.txt` (`-r` or `-c`).
**Learning:** Arbitrary paths could be injected because `os.path.abspath(os.path.join(..., inc_target))` allowed traversing up out of the project base directory when evaluating recursive inclusions.
**Prevention:** Use the `_is_safe_path` helper function to validate that resolved paths never escape the base project directory before proceeding to read and parse the file.
