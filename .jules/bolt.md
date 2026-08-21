## 2024-08-09 - Regex Recompilation Optimization
**Learning:** Python's `re.compile()` caches recently used expressions, but moving them to the global module scope entirely bypasses the cache lookup and function call overhead, yielding a minor (~10-20%) but measurable speedup on hot paths, especially when looping over items or tokens.
**Action:** When a static regex is used inside a frequently called function or loop (such as parsing or tokenization), always move it to global scope. Avoid caching `re.compile()` locally in a function if the pattern never changes.
## 2026-08-15 - Optimize membership checks in tight loops
**Learning:** Python tuple membership checks like `x in ("a", "b", "c")` have an O(N) lookup time. Using sets `x in {"a", "b", "c"}` optimizes this to O(1) hash map lookup, providing significant speedups especially for strings when run many times in parsing logic. However, care must be taken to not replace tuples in `for x in (...)` constructs, as sets are unordered and could break deterministic iteration.
**Action:** Always prefer set membership checks `in {"...", "..."}` over tuple membership checks `in ("...", "...")` for static comparisons, but strictly avoid them in iteration constructs.

## 2025-02-12 - Python Regular Expression Hot Loop Overhead
**Learning:** Python's dynamic regex matching functions (`re.match`, `re.search`, `re.sub` passing a string pattern) incur observable cache lookup and function call overhead, which degrades performance when executed inside tight hot loops (like parsing manifest dependencies).
**Action:** Always move static regexes into global module scope using `re.compile()` and directly call their corresponding methods (`.match()`, `.sub()`) during loops to bypass Python's dynamic evaluation overhead.
