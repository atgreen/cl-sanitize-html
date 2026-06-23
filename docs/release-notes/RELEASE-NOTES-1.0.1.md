# sanitize-html 1.0.1

**Release date:** 2026-06-22

This release fixes a security vulnerability identified by the
[CL-SEC initiative](https://github.com/CL-SEC/CL-SEC).  Users should
upgrade.

## Security Fixes

### CL-SEC-2026-0211 — Backslash protocol-relative URL bypass (MEDIUM)

The `protocol-allowed-p` function rejected protocol-relative URLs
beginning with `//` (the CL-SEC-2026-0132 fix), but not the backslash
equivalents.  Per the WHATWG URL Standard, a backslash is treated as a
forward slash in the authority position of http(s) URLs, so
`/\evil.com/x`, `\/evil.com`, and `\\evil.com` all resolve to the
protocol-relative reference `//evil.com/x` — yet they passed the
relative-URL allowance because the second character was not a literal
`/`.  This allowed an attacker to load resources from an arbitrary
domain via the `href`, `src`, `cite`, `poster`, `background`, and
`srcset` attributes (tracking pixels, IP/data exfiltration via
auto-loaded images, and open-redirect / phishing on links).  The
default policy was affected; no special configuration was required.

**Fix:** The relative-URL check now treats `/` and `\` alike.  A URL is
accepted as relative only when it starts with a single separator that is
not immediately followed by another separator, so `//`, `/\`, `\/`, and
`\\` are all rejected as protocol-relative.

## Acknowledgments

Security issue identified by the CL-SEC (Common Lisp Security
Initiative) automated audit.
