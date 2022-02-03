<!-- omit in toc -->
# XSS

<!-- omit in toc -->
## Table of Contents

- [Reflected XSS into HTML context with nothing encoded](#reflected-xss-into-html-context-with-nothing-encoded)

## Reflected XSS into HTML context with nothing encoded
Reference: https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

<!-- omit in toc -->
### Solution
1. Copy and paste the following into the search box: ``<script>alert(1)</script>``
2. Click "Search".