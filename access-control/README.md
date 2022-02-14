<!-- omit in toc -->
# Access control

<!-- omit in toc -->
## Table of Contents

- [Unprotected admin functionality](#unprotected-admin-functionality)
- [Unprotected admin functionality with unpredictable URL](#unprotected-admin-functionality-with-unpredictable-url)
- [User role controlled by request parameter](#user-role-controlled-by-request-parameter)
- [User role can be modified in user profile](#user-role-can-be-modified-in-user-profile)

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