<!-- omit in toc -->
# Access control

<!-- omit in toc -->
## Table of Contents

- [Unprotected admin functionality](#unprotected-admin-functionality)
- [Unprotected admin functionality with unpredictable URL](#unprotected-admin-functionality-with-unpredictable-url)
- [User role controlled by request parameter](#user-role-controlled-by-request-parameter)
- [User role can be modified in user profile](#user-role-can-be-modified-in-user-profile)
- [URL-based access control can be circumvented](#url-based-access-control-can-be-circumvented)

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

## User role controlled by request parameter
Reference: https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter

<!-- omit in toc -->
### Solution
1. Browse to ``/admin`` and observe that you can't access the admin panel.
2. Browse to the login page.
3. In Burp Proxy, turn interception on and enable response interception.
4. Complete and submit the login page, and forward the resulting request in Burp.
5. Observe that the response sets the cookie ``Admin=false``. Change it to ``Admin=true``.
6. Load the admin panel and delete ``carlos``.

## User role can be modified in user profile
Reference: https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile

<!-- omit in toc -->
### Solution
1. Log in using the supplied credentials and access your account page.
2. Use the provided feature to update the email address associated with your account.
3. Observe that the response contains your role ID.
4. Send the email submission request to Burp Repeater, add ``"roleid":2`` into the JSON in the request body, and resend it.
5. Observe that the response shows your ``roleid`` has changed to 2.
6. Browse to ``/admin`` and delete ``carlos``.

## URL-based access control can be circumvented
Reference: https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented

<!-- omit in toc -->
### Solution
1. Try to load ``/admin`` and observe that you get blocked. Notice that the response is very plain, suggesting it may originate from a front-end system.
2. Send the request to Burp Repeater. Change the URL in the request line to / and add the HTTP header ``X-Original-URL: /invalid``. Observe that the application returns a "not found" response. This indicates that the back-end system is processing the URL from the ``X-Original-URL`` header.
3. Change the value of the ``X-Original-URL`` header to ``/admin``. Observe that you can now access the admin page.
4. To delete the user ``carlos``, add ``?username=carlos`` to the real query string, and change the ``X-Original-URL`` path to ``/admin/delete``.