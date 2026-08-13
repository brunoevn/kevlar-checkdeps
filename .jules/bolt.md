## 2024-08-09 - Regex Recompilation Optimization
**Learning:** Python's `re.compile()` caches recently used expressions, but moving them to the global module scope entirely bypasses the cache lookup and function call overhead, yielding a minor (~10-20%) but measurable speedup on hot paths, especially when looping over items or tokens.
**Action:** When a static regex is used inside a frequently called function or loop (such as parsing or tokenization), always move it to global scope. Avoid caching `re.compile()` locally in a function if the pattern never changes.
## 2026-08-12 - Collection Membership Lookup Optimization
**Learning:** Checking for membership in a set (`{...}`) is significantly faster (O(1) time complexity) than checking in a tuple or list (O(n) time complexity) in Python, particularly in loops that execute millions of times.
**Action:** Always use sets (`in {"a", "b", "c"}`) rather than tuples or lists (`in ("a", "b", "c")`) for static collection membership tests.
