<!-- omit in toc -->
# Dreictory traversal

<!-- omit in toc -->
## Table of Contents

- [File path traversal, simple case](#file-path-traversal-simple-case)
- [File path traversal, traversal sequences blocked with absolute path bypass](#file-path-traversal-traversal-sequences-blocked-with-absolute-path-bypass)
- [File path traversal, traversal sequences stripped non-recursively](#file-path-traversal-traversal-sequences-stripped-non-recursively)

## File path traversal, simple case
Reference: https://portswigger.net/web-security/file-path-traversal/lab-simple

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the ``filename`` parameter, giving it the value:
```
../../../etc/passwd
```
3. Observe that the response contains the contents of the ``/etc/passwd`` file.

## File path traversal, traversal sequences blocked with absolute path bypass
Reference: https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the ``filename`` parameter, giving it the value ``/etc/passwd``.
3. Observe that the response contains the contents of the ``/etc/passwd`` file.

## File path traversal, traversal sequences stripped non-recursively
Reference: https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the ``filename`` parameter, giving it the value:
```
....//....//....//etc/passwd
```
3. Observe that the response contains the contents of the ``/etc/passwd`` file.