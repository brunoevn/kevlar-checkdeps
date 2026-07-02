# Dependency Status Report

Generated on 2026-07-01 22:12:02

## Summary

- **Total Checked**: 3
- **Up-to-date**: 1
- **Outdated**: 2 (Patch: 0, Minor: 0, Major: 2)
- **Deprecated**: 2
- **Security Vulnerabilities**: 4 found in 3 packages

## Dependency Details

| Package | Type | Declared | Installed | Latest | Status | Vuls | Note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `express` | Direct | `^4.17.1` | `4.17.1` | `5.2.1` | ❌ Major Update | ⚠️ **2** |  |
| `uuid` | Dev | `^9.0.0` | `9.0.0` | `14.0.1` | 🚫 Deprecated | ⚠️ **1** | Deprecation Warning: uuid@10 and below is no longer supported.  For ESM codebases, update to uuid@latest.  For CommonJS codebases, use uuid@11 (but be aware this version will likely be deprecated in 2028). |
| `request` | Direct | `^2.88.2` | `2.88.2` | `2.88.2` | 🚫 Deprecated | ⚠️ **1** | Deprecation Warning: request has been deprecated, see https://github.com/request/request/issues/3142 |

## Security Vulnerabilities Details

### `express@4.17.1` (2 vulnerabilities)

- **GHSA-qw6h-vgh9-j6wx** [CVSS CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L]: express vulnerable to XSS via response.redirect()
  > ### Impact
> 
> In express <4.20.0, passing untrusted user input - even after sanitizing it - to `response.redirect()` may execute untrusted code
> 
> ### Patches
> 
> this issue is patched in express 4.20.0
> 
> ### Workarounds
> 
> users are encouraged to upgrade to the patched version of express, but otherwise can workaround this issue by making sure any untrusted inputs are safe, ideally by validating them against an explicit allowlist
> 
> ### Details
> 
> successful exploitation of this vector requires the following:
> 
> 1. The attacker MUST control the input to response.redirect()
> 1. express MUST NOT redirect before the template appears
> 1. the browser MUST NOT complete redirection before:
> 1. the user MUST click on the link in the template
> 

- **GHSA-rv95-896h-c2vc** [CVSS CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N]: Express.js Open Redirect in malformed URLs
  > ### Impact
> 
> Versions of Express.js prior to 4.19.2 and pre-release alpha and beta versions before 5.0.0-beta.3 are affected by an open redirect vulnerability using malformed URLs.
> 
> When a user of Express performs a redirect using a user-provided URL Express performs an encode [using `encodeurl`](https://github.com/pillarjs/encodeurl) on the contents before passing it to the `location` header. This can cause malformed URLs to be evaluated in unexpected ways by common redirect allow list implementations in Express applications, leading to an Open Redirect via bypass of a properly implemented allow list.
> 
> The main method impacted is `res.location()` but this is also called from within `res.redirect()`.
> 
> ### Patches
> 
> https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd
> https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94
> 
> An initial fix went out with `express@4.19.0`, we then patched a feature regression in `4.19.1` and added improved handling for the bypass in `4.19.2`.
> 
> ### Workarounds
> 
> The fix for this involves pre-parsing the url string with either `require('node:url').parse` or `new URL`. These are steps you can take on your own before passing the user input string to `res.location` or `res.redirect`.
> 
> ### Resources
> 
> https://github.com/expressjs/express/pull/5539
> https://github.com/koajs/koa/issues/1800
> https://expressjs.com/en/4x/api.html#res.location

### `uuid@9.0.0` (1 vulnerabilities)

- **GHSA-w5hq-g745-h8pq** [CVSS CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N]: uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided
  > ### Summary
> 
> The `v3()`, `v5()`, and `v6()` [API methods](https://github.com/uuidjs/uuid#api-summary) (not `uuid` release versions) accept external output buffers but do not reject out-of-range writes (small `buf` or large `offset`).  
> By contrast, `v4()`, `v1()`, and `v7()` API methods explicitly throw `RangeError` on invalid bounds.
> 
> This inconsistency allows **silent partial writes** into caller-provided buffers.
> 
> 
> ### Affected code
> 
> - `src/v35.ts` (`v3()`/`v5()` path) writes `buf[offset + i]` without bounds validation.
> - `src/v6.ts` writes `buf[offset + i]` without bounds validation.
> 
> ### Reproducible PoC
> 
> ```bash
> cd /home/StrawHat/uuid
> npm ci
> npm run build
> 
> node --input-type=module -e "
> import {v4,v5,v6} from './dist-node/index.js';
> const ns='6ba7b810-9dad-11d1-80b4-00c04fd430c8';
> for (const [name,fn] of [
>   ['v4()',()=>v4({},new Uint8Array(8),4)],
>   ['v5()',()=>v5('x',ns,new Uint8Array(8),4)],
>   ['v6()',()=>v6({},new Uint8Array(8),4)],
> ]) {
>   try { fn(); console.log(name,'NO_THROW'); }
>   catch(e){ console.log(name,'THREW',e.name); }
> }"
> ```
> 
> Observed:
> 
> - `v4() THREW RangeError`
> - `v5() NO_THROW`
> - `v6() NO_THROW`
> 
> Example partial overwrite evidence captured during audit:
> 
> ```text
> same true buf [
>   170, 170, 170, 170,
>    75, 224, 100,  63
> ]
> v6 [
>   187, 187, 187, 187,
>    31,  19, 185,  64
> ]
> ```
> 
> ### Security impact
> 
> - **Primary**: integrity/robustness issue (silent partial output).
> - If an application assumes full UUID writes into preallocated buffers, this can produce malformed/truncated/partially stale identifiers without error.
> - In systems where caller-controlled offsets/buffer sizes are exposed indirectly, this may become a security-relevant logic flaw.
> 
> ### Suggested fix
> 
> Add the same guard used by `v4()`/`v1()`/`v7()`:
> 
> ```ts
> if (offset < 0 || offset + 16 > buf.length) {
>   throw new RangeError(`UUID byte range ${offset}:${offset + 15} is out of buffer bounds`);
> }
> ```
> 
> Apply to:
> 
> - `src/v35.ts` (covers `v3()` and `v5()`)
> - `src/v6.ts`

### `request@2.88.2` (1 vulnerabilities)

- **GHSA-p8p7-x288-28g6** [CVSS CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N]: Server-Side Request Forgery in Request
  > The `request` package through 2.88.2 for Node.js and the `@cypress/request` package prior to 3.0.0 allow a bypass of SSRF mitigations via an attacker-controller server that does a cross-protocol redirect (HTTP to HTTPS, or HTTPS to HTTP).
> 
> NOTE: The `request` package is no longer supported by the maintainer.

