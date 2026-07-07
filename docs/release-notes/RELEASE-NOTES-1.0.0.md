# sanitize-html 1.0.0

**Release date:** 2026-03-31

This release addresses **4 security vulnerabilities** identified by the
[CL-SEC initiative](https://github.com/CL-SEC), including 2 critical
XSS bypasses.  All users should upgrade immediately.

## Security Fixes

### CL-SEC-2026-0129 — Double-encoded entity reversal enables XSS (CRITICAL)

The `decode-double-encoded-entities` function performed post-serialization
regex rewriting of Plump's entity-encoded output, reversing safe encoding
back into active HTML characters.  This anti-pattern created a fragile
security boundary that could be bypassed.

**Fix:** The function has been removed entirely.  Plump's serializer
produces correct output; double-encoding is no longer an issue.

### CL-SEC-2026-0130 — SVG/MathML namespace enables mXSS (CRITICAL)

The sanitizer had no special handling for SVG or MathML elements.  These
were processed by the "remove tag, keep children" path, promoting their
content into the document.  SVG `<foreignObject>` and MathML
`<annotation-xml>` re-enter HTML parsing context, enabling mutation XSS
(mXSS) where the sanitizer's DOM tree differs from the browser's
re-parsing.

**Fix:** SVG, MathML, iframe, object, embed, applet, base, meta, link,
template, audio, video, source, track, param, xmp, listing, and
plaintext are now on the full-removal list — their content is discarded,
not promoted.

### CL-SEC-2026-0131 — CSS comment bypass in expression() check (HIGH)

The `css-value-dangerous-p` function did not strip CSS comments before
checking for dangerous keywords.  IE's CSS parser ignores comments, so
`exp/**/ression(alert(1))` was interpreted as `expression(alert(1))` by
the browser but bypassed the sanitizer's keyword check.

**Fix:** CSS comments are now stripped via `strip-css-comments` before
keyword matching.

### CL-SEC-2026-0132 — Protocol-relative URL bypass (MEDIUM)

Protocol-relative URLs (`//evil.com/track.gif`) passed the
`protocol-allowed-p` check because they start with `/`, which matched
the relative-URL allowance.  This enabled loading resources from
attacker-controlled domains.

**Fix:** The relative-URL check now rejects URLs starting with `//`.

## Other Changes

- Version bumped to 1.0.0 to reflect production readiness and the
  security audit milestone.
- Added GitHub Actions release workflow.

## Acknowledgments

Security issues identified by the CLSEC (Common Lisp Security
Initiative) automated audit.
