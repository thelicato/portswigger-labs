<!-- omit in toc -->
# SSRF

<!-- omit in toc -->
## Table of Contents

- [Basic SSRF against the local server](#basic-ssrf-against-the-local-server)

## Basic SSRF against the local server
Reference: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

<!-- omit in toc -->
### Solution
1. Browse to ``/admin`` and observe that you can't directly access the admin page.
2. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Change the URL in the ``stockApi`` parameter to ``http://localhost/admin``. This should display the administration interface.
4. Read the HTML to identify the URL to delete the target user, which is:
```
http://localhost/admin/delete?username=carlos
```
5. Submit this URL in the ``stockApi`` parameter, to deliver the SSRF attack.