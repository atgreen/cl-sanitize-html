;;; tests/sanitizer-tests.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2025 Anthony Green
;;;
;;; Test suite for HTML sanitization

(in-package #:sanitize-html/tests)

(in-suite sanitize-html-tests)

;;; Basic sanitization tests

(test test-empty-input
  "Test that empty or nil input is handled safely"
  (is (string= "" (sanitize nil)))
  (is (string= "" (sanitize ""))))

(test test-plain-text
  "Test that plain text passes through unchanged"
  (is (string= "Hello, world!" (sanitize "Hello, world!"))))

(test test-safe-html
  "Test that safe HTML is preserved"
  (let ((html "<p>This is <strong>safe</strong> HTML</p>"))
    (is (search "<p>" (sanitize html)))
    (is (search "<strong>" (sanitize html)))
    (is (search "safe" (sanitize html)))))

;;; XSS attack prevention

(test test-script-tag-removed
  "Test that script tags are removed"
  (let ((result (sanitize "<script>alert('XSS')</script><p>Content</p>")))
    (is (not (search "<script" result)))
    (is (not (search "alert" result)))
    (is (search "<p>" result))
    (is (search "Content" result))))

(test test-event-handlers-removed
  "Test that event handlers are removed"
  (let ((result (sanitize "<a href='#' onclick='alert(1)'>Click</a>")))
    (is (not (search "onclick" result)))
    (is (search "<a" result))
    (is (search "href" result))))

(test test-javascript-protocol
  "Test that javascript: protocol is blocked"
  (let ((result (sanitize "<a href='javascript:alert(1)'>Bad</a>")))
    (is (not (search "javascript:" result)))))

(test test-data-protocol-blocked-by-default
  "Test that data: protocol is blocked in default policy"
  (let ((result (sanitize "<img src='data:text/html,<script>alert(1)</script>'>")))
    (is (not (search "data:" result)))))

;;; Tag filtering

(test test-disallowed-tags-removed
  "Test that disallowed tags are removed but content preserved"
  (let ((result (sanitize "<center>Content</center>")))
    (is (not (search "<center" result)))
    (is (search "Content" result))))

(defvar *links-only-policy*
  (make-policy
   :allowed-tags '("a")
   :allowed-attributes '(("a" . ("href" "class")))
   :allowed-protocols '("ftp" "http" "https" "mailto" "relative")
   :remove-comments t))

(test test-nested-tags-removed
  "Disallowed tags should be removed recursively"
  (is (string-equal
       "Keyboard tips"
       (sanitize "<h3><h3>Keyboard</h3> <h3>tips</h3></h3>"
                 *links-only-policy*))))

(test test-nested-tags-removed1
  "Disallowed tags of different kinds should be removed recursively"
  (is (string-equal
       "Keyboard tips"
       (sanitize "<div id=\"article\"><h3>Keyboard</h3> tips</div>"
                 *links-only-policy*))))

(test test-form-elements-removed
  "Test that form elements are removed"
  (let ((result (sanitize "<form><input type='text'></form>")))
    (is (not (search "<form" result)))
    (is (not (search "<input" result)))))

(test test-object-embed-removed
  "Test that object and embed tags are removed"
  (is (not (search "<object" (sanitize "<object data='evil.swf'></object>"))))
  (is (not (search "<embed" (sanitize "<embed src='evil.swf'></embed>")))))

;;; Attribute filtering

(test test-safe-attributes-preserved
  "Test that safe attributes are preserved"
  (let ((result (sanitize "<a href='http://example.com' title='Example'>Link</a>")))
    (is (search "href" result))
    (is (search "title" result))
    (is (search "example.com" result))))

(test test-style-attribute-removed-by-default
  "Test that style attribute is removed in default policy"
  (let ((result (sanitize "<p style='color: red'>Text</p>")))
    (is (not (search "style" result)))))

(test test-class-and-id-preserved
  "Test that class and id attributes are preserved"
  (let ((result (sanitize "<div class='container' id='main'>Content</div>")))
    (is (search "class=\"container\"" result))
    (is (search "id=\"main\"" result))))

;;; URL sanitization

(test test-http-urls-allowed
  "Test that HTTP URLs are allowed"
  (let ((result (sanitize "<a href='http://example.com'>Link</a>")))
    (is (search "http://example.com" result))))

(test test-https-urls-allowed
  "Test that HTTPS URLs are allowed"
  (let ((result (sanitize "<a href='https://example.com'>Link</a>")))
    (is (search "https://example.com" result))))

(test test-mailto-urls-allowed
  "Test that mailto: URLs are allowed"
  (let ((result (sanitize "<a href='mailto:test@example.com'>Email</a>")))
    (is (search "mailto:test@example.com" result))))

(test test-relative-urls-allowed
  "Test that relative URLs are allowed"
  (let ((result (sanitize "<a href='/page'>Link</a>")))
    (is (search "/page" result))))

;;; Comment and CDATA handling

(test test-comments-removed
  "Test that HTML comments are removed by default"
  (let ((result (sanitize "<!-- comment --><p>Content</p>")))
    (is (not (search "<!--" result)))
    (is (not (search "comment" result)))
    (is (search "<p>" result))))

;;; Safe defaults

(test test-links-get-noopener
  "Test that links get rel='noopener noreferrer' added"
  (let ((result (sanitize "<a href='http://example.com'>Link</a>")))
    (is (search "noopener" result))
    (is (search "noreferrer" result))))

(test test-links-get-target-blank
  "Test that links get target='_blank' added"
  (let ((result (sanitize "<a href='http://example.com'>Link</a>")))
    (is (search "target=\"_blank\"" result))))

(test test-links-policy-not-target-blank
  "Policy specifies that anchors should not have target='_blank' set"
  (is (not (search "target=\"_blank\""
                   (sanitize
                    "<a href='http://example.com'>Link</a>"
                    (make-policy
                     :allowed-tags '("a")
                     :allowed-attributes '(("a" . ("href" "title" "rel")))
                     :override-anchor-target nil))))))

;;; Policy tests

(test test-strict-policy
  "Test that strict policy is more restrictive"
  (let ((html "<div><span class='test'>Content</span></div>"))
    ;; Default policy allows div and span
    (is (search "<div>" (sanitize html *default-policy*)))
    ;; Strict policy removes div but allows span with class attribute
    (let ((result (sanitize html *strict-policy*)))
      (is (not (search "<div" result)))  ; div should be removed
      (is (search "<span" result))        ; span should remain
      (is (search "class" result)))))

(test test-email-policy-allows-tables
  "Test that email policy allows table elements"
  (let* ((html "<table><tr><td>Cell</td></tr></table>")
         (result (sanitize html *email-policy*)))
    (is (search "<table>" result))
    (is (search "<tr>" result))
    (is (search "<td>" result))))

(test test-email-policy-allows-inline-styles
  "Test that email policy allows inline styles"
  (let* ((html "<p style='color: red; font-size: 14px'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (search "style" result))
    (is (search "color" result))))

(test test-email-policy-blocks-dangerous-css
  "Test that email policy blocks dangerous CSS"
  (let* ((html "<p style='color: red; behavior: url(xss.htc)'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "behavior" result)))
    (is (search "color" result))))

(test test-email-policy-allows-cid-urls
  "Test that email policy allows cid: URLs for inline images"
  (let* ((html "<img src='cid:image001@example.com'>")
         (result (sanitize html *email-policy*)))
    (is (search "cid:" result))))

;;; Edge cases

(test test-nested-tags
  "Test deeply nested tags"
  (let* ((html "<div><p><span><strong>Text</strong></span></p></div>")
         (result (sanitize html)))
    (is (search "<div>" result))
    (is (search "<p>" result))
    (is (search "<span>" result))
    (is (search "<strong>" result))))

(test test-malformed-html
  "Test that malformed HTML doesn't crash the sanitizer"
  (finishes (sanitize "<p>Unclosed"))
  (finishes (sanitize "<div><p></div></p>"))
  (finishes (sanitize "<<script>alert(1)</script>")))

(test test-unicode-content
  "Test that Unicode content is preserved"
  (let* ((html "<p>Hello 世界 🌍</p>")
         (result (sanitize html)))
    (is (search "世界" result))
    (is (search "🌍" result))))

(test test-html-entities
  "Test that HTML entities are preserved"
  (let* ((html "<p>&lt;script&gt; &amp; &quot;</p>")
         (result (sanitize html)))
    (is (search "&lt;" result))
    (is (search "&amp;" result))
    (is (search "&quot;" result))))

;;; Performance / stress tests

(test test-large-html
  "Test that large HTML documents can be sanitized"
  (let* ((large-html (with-output-to-string (s)
                       (dotimes (i 1000)
                         (format s "<p>Paragraph ~D with <strong>bold</strong> text.</p>" i)))))
    (finishes (sanitize large-html))
    (let ((result (sanitize large-html)))
      (is (> (length result) 0))
      (is (search "<p>" result)))))

;;; Utility function tests

(test test-safe-url-p
  "Test the safe-url-p utility function"
  (is (safe-url-p "http://example.com"))
  (is (safe-url-p "https://example.com"))
  (is (safe-url-p "mailto:test@example.com"))
  (is (safe-url-p "/relative/path"))
  (is (safe-url-p "#anchor"))
  (is (not (safe-url-p "javascript:alert(1)")))
  (is (not (safe-url-p "data:text/html,<script>alert(1)</script>"))))

;;; CSS escape bypass prevention tests

(test test-css-escape-backslash-bypass
  "Test that backslash escapes in CSS don't bypass sanitization"
  ;; java\script: should be blocked (backslash before 's')
  (let* ((html "<p style='background: url(java\\script:alert(1))'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "javascript" result)))
    (is (not (search "alert" result)))))

(test test-css-escape-hex-bypass
  "Test that hex escapes in CSS don't bypass sanitization"
  ;; \6a = 'j', so \6a avascript: = javascript:
  (let* ((html "<p style='background: url(\\6a avascript:alert(1))'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "javascript" result)))
    (is (not (search "alert" result)))))

(test test-css-escape-full-hex-bypass
  "Test that fully hex-encoded javascript: is blocked"
  ;; \6a\61\76\61\73\63\72\69\70\74 = javascript
  (let* ((html "<p style='background: url(\\6a\\61\\76\\61\\73\\63\\72\\69\\70\\74:alert(1))'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "url" result)))))

(test test-css-escape-expression-bypass
  "Test that escaped 'expression' is blocked"
  ;; expr\65ssion = expression (\65 = 'e')
  (let* ((html "<p style='width: expr\\65ssion(alert(1))'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "expression" result)))
    (is (not (search "alert" result)))))

(test test-css-escape-behavior-bypass
  "Test that escaped 'behavior' is blocked (IE-specific attack)"
  ;; b\65havior = behavior
  (let* ((html "<p style='behavior: url(xss.htc)'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "behavior" result)))))

(test test-css-escape-binding-bypass
  "Test that escaped '-moz-binding' is blocked"
  (let* ((html "<p style='-moz-binding: url(xss.xml#xss)'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "binding" result)))))

(test test-css-url-blocked
  "Test that url() is blocked even without javascript:"
  ;; Blocking url() entirely is safer
  (let* ((html "<p style='background: url(http://evil.com/track.gif)'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (not (search "url(" result)))))

(test test-css-safe-properties-still-work
  "Test that safe CSS properties without dangerous values still work"
  (let* ((html "<p style='color: red; font-size: 14px; margin: 10px'>Text</p>")
         (result (sanitize html *email-policy*)))
    (is (search "color" result))
    (is (search "font-size" result))
    (is (search "margin" result))))

;;; URL encoding bypass prevention tests

(test test-url-html-entity-decimal-bypass
  "Test that decimal HTML entities in URLs don't bypass protocol check"
  ;; &#106; = 'j', so &#106;avascript: = javascript:
  (let* ((html "<a href='&#106;avascript:alert(1)'>click</a>")
         (result (sanitize html)))
    (is (not (search "javascript" result)))
    (is (not (search "&#106;" result)))))

(test test-url-html-entity-hex-bypass
  "Test that hex HTML entities in URLs don't bypass protocol check"
  ;; &#x6a; = 'j', so &#x6a;avascript: = javascript:
  (let* ((html "<a href='&#x6a;avascript:alert(1)'>click</a>")
         (result (sanitize html)))
    (is (not (search "javascript" result)))
    (is (not (search "&#x6a;" result)))))

(test test-url-whitespace-bypass
  "Test that whitespace in URLs doesn't bypass protocol check"
  ;; Browsers may ignore whitespace/newlines in URL schemes
  (let* ((html "<a href='java
script:alert(1)'>click</a>")
         (result (sanitize html)))
    (is (not (search "script" result)))))

(test test-url-tab-bypass
  "Test that tabs in URLs don't bypass protocol check"
  (let* ((html (format nil "<a href='java~Cscript:alert(1)'>click</a>" #\Tab))
         (result (sanitize html)))
    (is (not (search "script" result)))))

(test test-url-leading-whitespace-bypass
  "Test that leading whitespace in URLs doesn't bypass protocol check"
  (let* ((html "<a href='   javascript:alert(1)'>click</a>")
         (result (sanitize html)))
    (is (not (search "javascript" result)))))

(test test-data-url-blocked-in-default
  "Test that data: URLs are blocked in default policy"
  (let* ((html "<img src='data:text/html,<script>alert(1)</script>'>")
         (result (sanitize html)))
    (is (not (search "data:" result)))))

(test test-data-url-blocked-in-email
  "Test that data: URLs are now blocked in email policy"
  (let* ((html "<img src='data:image/svg+xml,<svg onload=alert(1)>'>")
         (result (sanitize html *email-policy*)))
    (is (not (search "data:" result)))))

(test test-ping-attribute-removed
  "Test that ping attribute is always removed (tracking prevention)"
  (let* ((html "<a href='http://example.com' ping='http://tracker.com'>Link</a>")
         (result (sanitize html)))
    (is (not (search "ping" result)))
    (is (search "href" result))))

(test test-srcset-safe-urls-preserved
  "Test that safe URLs in srcset are preserved"
  (let* ((html "<img srcset='http://example.com/small.jpg 1x, https://example.com/large.jpg 2x'>")
         (result (sanitize html)))
    (is (search "srcset" result))
    (is (search "http://example.com/small.jpg" result))
    (is (search "https://example.com/large.jpg" result))))

(test test-srcset-unsafe-urls-removed
  "Test that unsafe URLs in srcset are removed"
  (let* ((html "<img srcset='javascript:alert(1) 1x, http://safe.com/img.jpg 2x'>")
         (result (sanitize html)))
    (is (not (search "javascript" result)))
    (is (search "http://safe.com" result))))

(test test-srcset-all-unsafe-removes-attribute
  "Test that srcset is removed if all URLs are unsafe"
  (let* ((html "<img srcset='javascript:alert(1) 1x, data:image/png;base64,xxx 2x'>")
         (result (sanitize html)))
    (is (not (search "srcset" result)))))

(test test-formaction-removed
  "Test that formaction attribute is removed"
  (let* ((html "<button formaction='javascript:alert(1)'>Submit</button>")
         (result (sanitize html)))
    (is (not (search "formaction" result)))))

(test test-xlink-href-removed
  "Test that xlink:href attribute is removed"
  (let* ((html "<a xlink:href='javascript:alert(1)'>Link</a>")
         (result (sanitize html)))
    (is (not (search "xlink:href" result)))))
