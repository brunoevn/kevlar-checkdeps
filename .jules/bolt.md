## 2024-08-09 - Regex Recompilation Optimization
**Learning:** Python's `re.compile()` caches recently used expressions, but moving them to the global module scope entirely bypasses the cache lookup and function call overhead, yielding a minor (~10-20%) but measurable speedup on hot paths, especially when looping over items or tokens.
**Action:** When a static regex is used inside a frequently called function or loop (such as parsing or tokenization), always move it to global scope. Avoid caching `re.compile()` locally in a function if the pattern never changes.

## 2026-08-13 - Membership Checks Optimization and Formatting Footprint
**Learning:** Python optimizes set literal membership (`in {...}`) to O(1) frozenset lookups, but changing tuples to sets in `for` loops breaks deterministic iteration order. Also, running file-wide formatters (`black`, `ruff --fix`) breaks the "< 50 lines" change constraint.
**Action:** Prefer `in {...}` for membership testing, but never in `for` loops. Avoid running whole-file auto-formatters when under small PR constraints; use targeted patches instead.
