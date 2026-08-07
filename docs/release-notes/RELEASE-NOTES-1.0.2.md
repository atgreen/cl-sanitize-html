# sanitize-html 1.0.2

**Release date:** 2026-08-07

This release fixes two security vulnerabilities identified by the
[CL-SEC initiative](https://github.com/CL-SEC/CL-SEC).  Users should
upgrade.

## Security Fixes

### CL-SEC-2026-0214 — Comment-breakout XSS with preserved comments (MEDIUM)

When a policy is configured with `:remove-comments nil` (a non-default
option; the built-in default, strict, and email policies remove
comments), comment content was serialized verbatim.  Plump ends a comment
only at `-->`, but browsers also end one at `--!>` and via the abrupt
`<!-->` / `<!--->` forms, and Plump decodes entities in comment text
while emitting it raw.  A preserved comment such as
`<!-- --!><img src=x onerror=alert(1)> -->` therefore round-tripped
unchanged and a browser re-parsed it as comment-end followed by live
markup — executing the injected handler.  Entity-encoded terminators
(`&#45;&#45;!>`, `&#45;&#45;&#62;`) reached the same sink.

**Fix:** Preserved comment text is now neutralized before serialization,
operating on Plump's already-decoded text so entity-encoded terminators
are covered.  Runs of hyphens are collapsed so `--` — and thus `-->`,
`--!>`, and `<!--` — cannot appear, and a leading `>`/`-` or trailing `-`
is padded so the abrupt-close and closing-delimiter merge cases cannot
form.  The default policies remove comments and were unaffected.

### CL-SEC-2026-0215 — Denial of service via deeply nested input (MEDIUM)

`sanitize-html` documented that it returns an empty string for safety when
parsing fails, but its `handler-case` caught only `error`.  Deeply nested
HTML overflows the control stack inside Plump's recursive parser, which
signals `control-stack-exhausted` — a `storage-condition`, not an `error`
— so it escaped the guard and propagated to the caller as an unhandled
condition.  Roughly 20,000 nested elements (about 98 KB, closing tags not
even required) were sufficient to crash the calling thread.

**Fix:** The guard now catches `(or storage-condition error)`.  Because
`handler-case` unwinds the deep stack before running the handler,
returning `""` is reliable.  Interrupts and other non-storage
serious-conditions still propagate.

## Acknowledgments

Security issues identified by the CL-SEC (Common Lisp Security
Initiative) automated audit.
