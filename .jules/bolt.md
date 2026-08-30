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

## $(date +%Y-%m-%d) - [O(n) BFS Traversal in find_direct_parents]
**Learning:** Using `queue.pop(0)` on a standard Python list inside a BFS `while` loop makes the traversal O(V²) instead of O(V+E) because popping from the start of a list requires shifting all subsequent elements, which is an O(n) operation.
**Action:** Always use `collections.deque.popleft()` or a read pointer index (`queue_idx += 1`) when implementing queue-based processing in Python to ensure O(1) dequeue performance.

## 2024-05-18 - Functools LRU Cache for Dynamic Regex Packages
**Learning:** Python's dynamic regex matching functions incur observable cache lookup and function call overhead, which degrades performance when executed inside tight hot loops (like parsing manifest dependencies). When a regex incorporates dynamic components (such as a package name, which prevents simply using a global `re.compile` at the module level), using `@functools.lru_cache(maxsize=1024)` on a helper function that compiles and returns the `re.compile` object yields a ~5x performance improvement because it bypasses the `re.search` overhead and only compiles dynamic regexes once per unique string.
**Action:** Replace `re.search(r"some_pattern" + package_name)` in hot loops with a helper function decorated with `@functools.lru_cache` that returns the `re.compile` object, and call `.search()` on it. This combines the benefits of static recompilation while allowing dynamically interpolated variables in the pattern.
## 2026-08-30 - Python Regex Hot Loop Global Module Scope
**Learning:** While Python's `re.compile()` caches recent expressions, moving them to global scope completely bypasses cache lookup overhead and method call instantiation. Using `.match()` and `.search()` directly from these globals prevents latency in repeatedly executed tight loop parses, like scanning long files line by line.
**Action:** Define complex inline regexes in global variables using `re.compile()` for code blocks running iteratively across many records or lines.
