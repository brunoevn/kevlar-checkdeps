## 2024-08-09 - Regex Recompilation Optimization
**Learning:** Python's `re.compile()` caches recently used expressions, but moving them to the global module scope entirely bypasses the cache lookup and function call overhead, yielding a minor (~10-20%) but measurable speedup on hot paths, especially when looping over items or tokens.
**Action:** When a static regex is used inside a frequently called function or loop (such as parsing or tokenization), always move it to global scope. Avoid caching `re.compile()` locally in a function if the pattern never changes.
## 2026-08-15 - Optimize membership checks in tight loops
**Learning:** Python tuple membership checks like `x in ("a", "b", "c")` have an O(N) lookup time. Using sets `x in {"a", "b", "c"}` optimizes this to O(1) hash map lookup, providing significant speedups especially for strings when run many times in parsing logic. However, care must be taken to not replace tuples in `for x in (...)` constructs, as sets are unordered and could break deterministic iteration.
**Action:** Always prefer set membership checks `in {"...", "..."}` over tuple membership checks `in ("...", "...")` for static comparisons, but strictly avoid them in iteration constructs.

## 2025-02-12 - Python Regular Expression Hot Loop Overhead
**Learning:** Python's dynamic regex matching functions (`re.match`, `re.search`, `re.sub` passing a string pattern) incur observable cache lookup and function call overhead, which degrades performance when executed inside tight hot loops (like parsing manifest dependencies).
**Action:** Always move static regexes into global module scope using `re.compile()` and directly call their corresponding methods (`.match()`, `.sub()`) during loops to bypass Python's dynamic evaluation overhead.

## 2026-08-23 - re.compile module cache bypass for CVSS severity parsing
**Learning:** In Python, `re.search()` with a string pattern requires a lookup in the `re` module's internal cache every time it's called. By using `re.compile()` at the module level and calling `.search()` directly on the compiled object, the code avoids this cache lookup, making execution slightly faster. This is a classic and highly effective micro-optimization for functions that are called repeatedly in a loop.
**Action:** Move static regexes (using `re.compile()`) to the global module scope instead of caching them locally within frequently called functions or loops, as it bypasses cache lookup and function call overhead.
## 2026-08-25 - Optimize BFS Traversal Dequeue Operation
**Learning:** In Python, `list.pop(0)` is an O(N) operation because it shifts all subsequent elements. When used inside a loop like a BFS queue processor, it turns an O(N) algorithm into an O(N^2) bottleneck. Using a read index tracking pointer achieves O(1) dequeue performance without requiring external imports like `collections.deque`.
**Action:** Whenever implementing a queue with a standard Python list, use a read pointer (e.g. `head = 0`, `item = queue[head]`, `head += 1`) or import `collections.deque` instead of using `list.pop(0)` to maintain optimal performance.
