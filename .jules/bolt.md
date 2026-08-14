## 2024-08-09 - Regex Recompilation Optimization
**Learning:** Python's `re.compile()` caches recently used expressions, but moving them to the global module scope entirely bypasses the cache lookup and function call overhead, yielding a minor (~10-20%) but measurable speedup on hot paths, especially when looping over items or tokens.
**Action:** When a static regex is used inside a frequently called function or loop (such as parsing or tokenization), always move it to global scope. Avoid caching `re.compile()` locally in a function if the pattern never changes.

## 2024-08-14 - Tuple to Set Conversion in Loops
**Learning:** While converting static tuple membership checks (`in (...)`) to set membership checks (`in {...}`) improves performance due to $O(1)$ lookups, doing this for iterables inside `for` loops (e.g. `for x in (...)`) breaks deterministic iteration because sets are unordered. This can break logic that relies on order, like semver parsing.
**Action:** When converting static tuples to sets to optimize membership checks, never convert them in `for` loops. Always use regex or manual checks to ignore iterables that follow `for` keywords.
