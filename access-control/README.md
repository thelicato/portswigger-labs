<!-- omit in toc -->
# Access control

<!-- omit in toc -->
## Table of Contents

- [Unprotected admin functionality](#unprotected-admin-functionality)
- [Unprotected admin functionality with unpredictable URL](#unprotected-admin-functionality-with-unpredictable-url)

## Unprotected admin functionality
Reference: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality

<!-- omit in toc -->
### Solution
1. Go to the lab and view ``robots.txt`` by appending ``/robots.txt`` to the lab URL. Notice that the ``Disallow`` line discloses the path to the admin panel.
2. In the URL bar, replace ``/robots.txt`` with ``/administrator-panel`` to load the admin panel.
3. Delete ``carlos``.

## Unprotected admin functionality with unpredictable URL
Reference: https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url

<!-- omit in toc -->
### Solution
1. Review the lab home page's source using Burp Suite or your web browser's developer tools.
2. Observe that it contains some JavaScript that discloses the URL of the admin panel.
3. Load the admin panel and delete ``carlos``.