<!-- omit in toc -->
# Access control

<!-- omit in toc -->
## Table of Contents

- [Unprotected admin functionality](#unprotected-admin-functionality)
- [Unprotected admin functionality with unpredictable URL](#unprotected-admin-functionality-with-unpredictable-url)
- [User role controlled by request parameter](#user-role-controlled-by-request-parameter)
- [User role can be modified in user profile](#user-role-can-be-modified-in-user-profile)
- [URL-based access control can be circumvented](#url-based-access-control-can-be-circumvented)
- [Method-based access control can be circumvented](#method-based-access-control-can-be-circumvented)
- [User ID controlled by request parameter](#user-id-controlled-by-request-parameter)
- [User ID controlled by request parameter, with unpredictable user IDs](#user-id-controlled-by-request-parameter-with-unpredictable-user-ids)
- [User ID controlled by request parameter with data leakage in redirect](#user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)
- [User ID controlled by request parameter with password disclosure](#user-id-controlled-by-request-parameter-with-password-disclosure)
- [Insecure direct object references](#insecure-direct-object-references)
- [Multi-step process with no access control on one step](#multi-step-process-with-no-access-control-on-one-step)
- [Referer-based access control](#referer-based-access-control)

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

## Method-based access control can be circumvented
Reference: https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented

<!-- omit in toc -->
### Solution
1. Log in using the admin credentials.
2. Browse to the admin panel, promote ``carlos``, and send the HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Attempt to re-promote ``carlos`` with the non-admin user by copying that user's session cookie into the existing Burp Repeater request, and observe that the response says "Unauthorized".
5. Change the method from ``POST`` to ``POSTX`` and observe that the response changes to "missing parameter".
6. Convert the request to use the ``GET`` method by right-clicking and selecting "Change request method".
7. Change the username parameter to your username and resend the request.

## User ID controlled by request parameter
Reference: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter

<!-- omit in toc -->
### Solution
1. Log in using the supplied credentials and go to your account page.
2. Note that the URL contains your username in the "id" parameter.
3. Send the request to Burp Repeater.
4. Change the "id" parameter to ``carlos``.
5. Retrieve and submit the API key for ``carlos``.

## User ID controlled by request parameter, with unpredictable user IDs
Reference: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids

<!-- omit in toc -->
### Solution
1. Find a blog post by ``carlos``.
2. Click on ``carlos`` and observe that the URL contains his user ID. Make a note of this ID.
3. Log in using the supplied credentials and access your account page.
4. Change the "id" parameter to the saved user ID.
5. Retrieve and submit the API key.

## User ID controlled by request parameter with data leakage in redirect
Reference: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect

<!-- omit in toc -->
### Solution
1. Log in using the supplied credentials and access your account page.
2. Send the request to Burp Repeater.
3. Change the "id" parameter to ``carlos``.
4. Observe that although the response is now redirecting you to the home page, it has a body containing the API key belonging to ``carlos``.
5. Submit the API key.

## User ID controlled by request parameter with password disclosure
Reference: https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure

<!-- omit in toc -->
### Solution
1. Log in using the supplied credentials and access the user account page.
2. Change the "id" parameter in the URL to ``administrator``.
3. View the response in Burp and observe that it contains the administrator's password.
4. Log in to the administrator account and delete ``carlos``.

## Insecure direct object references
Reference: https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

<!-- omit in toc -->
### Solution
1. Select the **Live chat** tab.
2. Send a message and then select **View transcript**.
3. Review the URL and observe that the transcripts are text files assigned a filename containing an incrementing number.
4. Change the filename to ``1.txt`` and review the text. Notice a password within the chat transcript.
5. Return to the main lab page and log in using the stolen credentials.

## Multi-step process with no access control on one step
Reference: https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step

<!-- omit in toc -->
### Solution
1. Log in using the admin credentials.
2. Browse to the admin panel, promote ``carlos``, and send the confirmation HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Copy the non-admin user's session cookie into the existing Repeater request, change the username to yours, and replay it.

## Referer-based access control
Reference: https://portswigger.net/web-security/access-control/lab-referer-based-access-control

<!-- omit in toc -->
### Solution
1. Log in using the admin credentials.
2. Browse to the admin panel, promote ``carlos``, and send the HTTP request to Burp Repeater.
3. Open a private/incognito browser window, and log in with the non-admin credentials.
4. Browse to ``/admin-roles?username=carlos&action=upgrade`` and observe that the request is treated as unauthorized due to the absent Referer header.
5. Copy the non-admin user's session cookie into the existing Burp Repeater request, change the username to yours, and replay it.