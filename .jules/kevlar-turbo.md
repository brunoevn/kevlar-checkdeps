## 2026-07-11 - [Formatter Side Effects in Python Optimization]
**Learning:** Using an auto-formatter like `black` on an entire existing codebase can introduce massive side effects that violate strict "small PR footprint" (e.g., < 60 lines) constraints.
**Action:** When working in strict boundary constraints, manually craft precise replacements (via `replace` string operations or small targeted patches) rather than running whole-file linters/formatters that mutate untouched code.
