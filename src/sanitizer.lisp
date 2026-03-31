;;; sanitizer.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2025 Anthony Green
;;;
;;; Core HTML sanitization logic

(in-package #:sanitize-html)

;;; CL-SEC-2026-0129: decode-double-encoded-entities was removed.
;;; Post-serialization regex rewriting of entity-encoded output is an
;;; anti-pattern that creates a fragile security boundary.  Plump's
;;; serializer produces correct output; double-encoding was a symptom
;;; of encoding text that already contained entity references, which
;;; should be handled by not double-encoding in the first place.

(defun sanitize-html (html-string &optional (policy *default-policy*))
  "Sanitize HTML-STRING according to POLICY. Returns sanitized HTML string.
   This is the main entry point for HTML sanitization."
  (when (null html-string)
    (return-from sanitize-html ""))

  (handler-case
      (let* ((root (plump:parse html-string))
             ;; Sanitize all children of root
             (_ (sanitize-node root policy))
             ;; Serialize back to HTML
             (serialized (plump:serialize root nil)))
        (declare (ignore _))
        serialized)
    (error (e)
      ;; If parsing fails, return empty string for safety
      (format *error-output* "HTML sanitization error: ~A~%" e)
      "")))

(defun sanitize (html-string &optional (policy *default-policy*))
  "Alias for SANITIZE-HTML"
  (sanitize-html html-string policy))

(defgeneric sanitize-node (node policy)
  (:documentation "Sanitize a Plump DOM node according to policy"))

(defun sanitize-children (node policy)
  (let ((children (plump:children node)))
    ;; Iterate in reverse order because recursive sanitizing may mutate children.
    (loop for i from (1- (length children)) downto 0
          for child = (aref children i)
          do (sanitize-node child policy))))

(defmethod sanitize-node ((node plump:root) policy)
  "Sanitize all children of root node"
  (sanitize-children node policy))

(defmethod sanitize-node ((node plump:element) policy)
  "Sanitize an HTML element node"
  (let ((tag-name (plump:tag-name node)))
    (cond
      ;; Tag is not allowed - remove it
      ((not (tag-allowed-p policy tag-name))
       ;; For dangerous tags (script, style, form elements), remove entirely including content
       ;; For other tags, just remove the tag but keep children
       (if (member (string-downcase tag-name)
                   '("script" "style" "noscript" "form" "input" "button"
                     "textarea" "select" "option" "optgroup" "fieldset" "legend"
                     ;; CL-SEC-2026-0130/0133: SVG/MathML and other dangerous elements
                     ;; whose children must NOT be promoted into the document.
                     "svg" "math" "iframe" "object" "embed" "applet"
                     "base" "meta" "link" "template"
                     "audio" "video" "source" "track" "param"
                     "xmp" "listing" "plaintext")
                   :test #'string-equal)
           (plump:remove-child node)
           (progn
             (sanitize-children node policy)
             (remove-element-keep-children node))))

      ;; Tag is allowed - sanitize attributes and recurse to children
      (t
       (sanitize-attributes node policy)
       (sanitize-children node policy)))))

(defmethod sanitize-node ((node plump:text-node) policy)
  "Text nodes are always safe, no action needed"
  (declare (ignore policy))
  node)

(defmethod sanitize-node ((node plump:comment) policy)
  "Remove or keep comment nodes based on policy"
  (when (policy-remove-comments policy)
    (plump:remove-child node)))

(defmethod sanitize-node ((node plump:cdata) policy)
  "Handle CDATA sections based on policy"
  (if (policy-escape-cdata policy)
      ;; Convert CDATA to text node
      (let ((text (plump:text node)))
        (plump:make-text-node (plump:parent node) text)
        (plump:remove-child node))
      ;; Keep CDATA as-is
      node))

(defmethod sanitize-node (node policy)
  "Default case for unknown node types - remove them"
  (declare (ignore policy))
  (when (plump:parent node)
    (plump:remove-child node)))

(defun remove-element-keep-children (element)
  "Remove ELEMENT but keep its children in the same position"
  (let ((parent (plump:parent element))
        (children (coerce (plump:children element) 'list)))
    (when parent
      ;; Insert each child before the element
      (dolist (child children)
        (plump:insert-before element child))
      ;; Remove the element
      (plump:remove-child element))))

(defun sanitize-attributes (element policy)
  "Remove disallowed attributes from ELEMENT according to POLICY"
  (let* ((tag-name (plump:tag-name element))
         (attrs (plump:attributes element))
         (attr-names nil))

    ;; Collect attribute names (attrs is a hash table)
    (maphash (lambda (k v)
               (declare (ignore v))
               (push k attr-names))
             attrs)

    ;; Remove disallowed attributes
    (dolist (attr-name attr-names)
      (unless (attribute-allowed-p policy tag-name attr-name)
        (plump:remove-attribute element attr-name)))

    ;; Sanitize URL attributes
    (sanitize-url-attribute element "href" policy)
    (sanitize-url-attribute element "src" policy)
    (sanitize-url-attribute element "cite" policy)
    (sanitize-url-attribute element "poster" policy)
    (sanitize-url-attribute element "background" policy)

    ;; Handle srcset specially (contains multiple URLs)
    (sanitize-srcset-attribute element policy)

    ;; Remove dangerous attributes that could leak data or enable attacks
    (remove-dangerous-attributes element)

    ;; Sanitize style attribute if present
    (when (plump:attribute element "style")
      (sanitize-style-attribute element policy))

    ;; Remove event handler attributes (onclick, onload, etc.)
    (remove-event-handlers element)

    ;; Set safe defaults for certain attributes
    (set-safe-defaults element policy)))

(defun sanitize-url-attribute (element attr-name policy)
  "Sanitize URL in attribute ATTR-NAME of ELEMENT"
  (when-let ((url (plump:attribute element attr-name)))
    (unless (protocol-allowed-p policy url)
      (plump:remove-attribute element attr-name))))

(defun sanitize-srcset-attribute (element policy)
  "Sanitize srcset attribute which contains multiple URLs with descriptors.
   Format: 'url1 1x, url2 2x' or 'url1 100w, url2 200w'"
  (when-let ((srcset (plump:attribute element "srcset")))
    (let ((parts (cl-ppcre:split "," srcset))
          (safe-parts nil))
      (dolist (part parts)
        (let* ((trimmed (string-trim '(#\Space #\Tab) part))
               ;; Split on whitespace to get URL and descriptor
               (tokens (cl-ppcre:split "\\s+" trimmed)))
          (when (and tokens (> (length tokens) 0))
            (let ((url (first tokens)))
              ;; Only keep if URL is safe
              (when (protocol-allowed-p policy url)
                (push trimmed safe-parts))))))
      (if safe-parts
          (plump:set-attribute element "srcset"
                               (format nil "~{~A~^, ~}" (nreverse safe-parts)))
          (plump:remove-attribute element "srcset")))))

(defun remove-dangerous-attributes (element)
  "Remove attributes that could be used for tracking or attacks.
   These are removed regardless of policy."
  ;; ping attribute on <a> can be used for tracking/data exfiltration
  (plump:remove-attribute element "ping")
  ;; formaction can override form action (XSS vector)
  (plump:remove-attribute element "formaction")
  ;; xlink:href for SVG (XSS vector if SVG allowed)
  (plump:remove-attribute element "xlink:href")
  ;; data-* attributes could potentially be exploited
  ;; but are commonly used legitimately, so we leave them
  )

(defun sanitize-style-attribute (element policy)
  "Sanitize inline CSS in style attribute"
  (let ((style (plump:attribute element "style"))
        (allowed-props (policy-allowed-css-properties policy)))
    (if (null allowed-props)
        ;; No CSS properties allowed, remove style
        (plump:remove-attribute element "style")
        ;; Parse and filter CSS properties
        (let ((sanitized-style (sanitize-css style allowed-props)))
          (if (and sanitized-style (> (length sanitized-style) 0))
              (plump:set-attribute element "style" sanitized-style)
              (plump:remove-attribute element "style"))))))

(defun hex-char-p (char)
  "Return T if CHAR is a hexadecimal digit"
  (or (digit-char-p char)
      (find char "abcdefABCDEF")))

(defun decode-css-escapes (css-string)
  "Decode CSS escape sequences in CSS-STRING.
   CSS escapes are:
   - Backslash followed by 1-6 hex digits (optional trailing whitespace consumed)
   - Backslash followed by any other character (literal escape)
   Returns the decoded string for security checking."
  (when (null css-string)
    (return-from decode-css-escapes ""))

  (with-output-to-string (out)
    (let ((len (length css-string))
          (i 0))
      (loop while (< i len) do
        (let ((char (char css-string i)))
          (if (char= char #\\)
              ;; Found backslash - check for escape sequence
              (if (>= (1+ i) len)
                  ;; Trailing backslash - output as-is
                  (progn
                    (write-char char out)
                    (incf i))
                  ;; Check what follows the backslash
                  (let ((next-char (char css-string (1+ i))))
                    (cond
                      ;; Hex escape: \XX or \XXXXXX
                      ((hex-char-p next-char)
                       (let ((hex-start (1+ i))
                             (hex-end (1+ i)))
                         ;; Collect up to 6 hex digits
                         (loop while (and (< hex-end len)
                                          (< (- hex-end hex-start) 6)
                                          (hex-char-p (char css-string hex-end)))
                               do (incf hex-end))
                         ;; Parse the hex value
                         (let* ((hex-str (subseq css-string hex-start hex-end))
                                (code-point (parse-integer hex-str :radix 16)))
                           ;; Output the character (if valid)
                           (when (and (> code-point 0) (<= code-point #x10FFFF))
                             (write-char (code-char code-point) out))
                           ;; Skip optional trailing whitespace (space, tab, newline)
                           (when (and (< hex-end len)
                                      (member (char css-string hex-end)
                                              '(#\Space #\Tab #\Newline #\Return #\Page)))
                             (incf hex-end))
                           (setf i hex-end))))
                      ;; Newline escapes are ignored (line continuation)
                      ((member next-char '(#\Newline #\Return #\Page))
                       (incf i 2))
                      ;; Any other character: just output it literally
                      (t
                       (write-char next-char out)
                       (incf i 2)))))
              ;; Regular character - output as-is
              (progn
                (write-char char out)
                (incf i))))))))

(defun strip-css-comments (css-string)
  "Remove CSS comments /* ... */ from CSS-STRING.
   CL-SEC-2026-0131: CSS comments must be stripped before keyword checks
   because IE's CSS parser ignores comments, so exp/**/ression() is
   interpreted as expression()."
  (cl-ppcre:regex-replace-all "/\\*.*?\\*/" css-string ""))

(defun css-value-dangerous-p (prop-value)
  "Check if a CSS property value contains dangerous content.
   Decodes CSS escapes and strips comments before checking."
  (let ((decoded (string-downcase
                  (strip-css-comments
                   (decode-css-escapes prop-value)))))
    (or (search "javascript:" decoded)
        (search "expression" decoded)
        (search "import" decoded)
        (search "@import" decoded)
        (search "url(" decoded)
        (search "behavior" decoded)
        (search "binding" decoded)
        (search "-moz-binding" decoded))))

(defun sanitize-css (css-string allowed-properties)
  "Sanitize CSS string, keeping only allowed properties"
  (when (null css-string)
    (return-from sanitize-css ""))

  (let ((properties nil)
        (parts (cl-ppcre:split ";" css-string)))
    (dolist (part parts)
      (let* ((trimmed (string-trim '(#\Space #\Tab #\Newline) part))
             (colon-pos (position #\: trimmed)))
        (when (and colon-pos (> colon-pos 0))
          (let* ((prop-name (string-trim '(#\Space #\Tab)
                                        (subseq trimmed 0 colon-pos)))
                 (prop-value (string-trim '(#\Space #\Tab)
                                         (subseq trimmed (1+ colon-pos)))))
            ;; Check if property is allowed and validate value (with escape decoding)
            (when (and (member (string-downcase prop-name)
                              allowed-properties
                              :test #'string-equal)
                       (not (css-value-dangerous-p prop-value)))
              (push (format nil "~A: ~A" prop-name prop-value) properties))))))

    (format nil "~{~A~^; ~}" (nreverse properties))))

(defun remove-event-handlers (element)
  "Remove all event handler attributes (onclick, onload, etc.)"
  (let ((attrs (plump:attributes element))
        (handlers nil))
    ;; Collect event handler attribute names
    (maphash (lambda (k v)
               (declare (ignore v))
               (when (and (>= (length k) 2)
                         (string-equal "on" (subseq k 0 2)))
                 (push k handlers)))
             attrs)
    ;; Remove them
    (dolist (attr-name handlers)
      (plump:remove-attribute element attr-name))))

(defun set-safe-defaults (element policy)
  "Set safe default attributes on certain elements"
  (let ((tag-name (plump:tag-name element)))
    ;; Links should open in new window and have safe rel
    (when (and (string-equal tag-name "a")
               (plump:attribute element "href"))
      ;; Set rel="noopener noreferrer" for security
      (if-let ((existing-rel (plump:attribute element "rel")))
        (unless (or (search "noopener" existing-rel)
                    (search "noreferrer" existing-rel))
          (plump:set-attribute element "rel"
                               (format nil "~A noopener noreferrer" existing-rel)))
        (plump:set-attribute element "rel" "noopener noreferrer"))
      (when (policy-override-anchor-target policy)
        (plump:set-attribute element "target"
                             (policy-override-anchor-target policy))))))

;;; Utility functions

(defun safe-url-p (url &optional (policy *default-policy*))
  "Check if URL is safe according to POLICY"
  (protocol-allowed-p policy url))

(defun sanitize-url (url &optional (policy *default-policy*))
  "Return URL if safe, nil otherwise"
  (when (safe-url-p url policy)
    url))
