<!-- omit in toc -->
# CSRF

<!-- omit in toc -->
## Table of Contents

- [CSRF vulnerability with no defenses](#csrf-vulnerability-with-no-defenses)
- [CSRF where token validation depends on request method](#csrf-where-token-validation-depends-on-request-method)
- [CSRF where token validation depends on token being present](#csrf-where-token-validation-depends-on-token-being-present)
- [CSRF where token is not tied to user session](#csrf-where-token-is-not-tied-to-user-session)

## CSRF vulnerability with no defenses
Reference: https://portswigger.net/web-security/csrf/lab-no-defenses

<!-- omit in toc -->
### Quick Solution
Just use the PoC generator of Burp and place it in the exploit server. It just works.

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. If you're using Burp Suite Professional, right-click on the request and select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
Alternatively, if you're using Burp Suite Community Edition, use the following HTML template and fill in the request's method, URL, and body parameters. You can get the request URL by right-clicking and selecting "Copy URL".
```html
<form method="$method" action="$url">
     <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
      document.forms[0].submit();
</script>
```
3. Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
4. To verify that the exploit works, try it on yourself by clicking "View exploit" and then check the resulting HTTP request and response.
5. Click "Deliver to victim" to solve the lab.

## CSRF where token validation depends on request method
Reference: https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method

<!-- omit in toc -->
### Quick Solution
The payload is exactly the same of the previous lab except for the request method (use **GET** instead of **POST**).

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that if you change the value of the ``csrf`` parameter then the request is rejected.
3. Use "Change request method" on the context menu to convert it into a GET request and observe that the CSRF token is no longer verified.
4. If you're using Burp Suite Professional, right-click on the request, and from the context menu select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
Alternatively, if you're using Burp Suite Community Edition, use the following HTML template and fill in the request's method, URL, and body parameters. You can get the request URL by right-clicking and selecting "Copy URL".
```html
<form method="$method" action="$url">
     <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
      document.forms[0].submit();
</script>
```
5. Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
6. To verify if the exploit will work, try it on yourself by clicking "View exploit" and checking the resulting HTTP request and response.
7. Click "Deliver to victim" to solve the lab.

## CSRF where token validation depends on token being present
Reference: https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present

<!-- omit in toc -->
### Quick Solution
Use the CSRF PoC generator from Burp and then just **remove** the ``csrf`` parameter.

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that if you change the value of the csrf parameter then the request is rejected.
3. Delete the ``csrf`` parameter entirely and observe that the request is now accepted.
4. If you're using Burp Suite Professional, right-click on the request, and from the context menu select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
Alternatively, if you're using Burp Suite Community Edition, use the following HTML template and fill in the request's method, URL, and body parameters. You can get the request URL by right-clicking and selecting "Copy URL".
```html
<form method="$method" action="$url">
     <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
      document.forms[0].submit();
</script>
```
5. Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
6. To verify if the exploit will work, try it on yourself by clicking "View exploit" and checking the resulting HTTP request and response.
7. Click "Deliver to victim" to solve the lab.

## CSRF where token is not tied to user session
Reference: https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session

<!-- omit in toc -->
### Quick Solution
In this case there is a **CSRF token**, but it is not tied to user session. To exploit this one intercept a request, note the ``csrf`` value, generate a PoC and deliver it to the victim (without forwarding the initial request).

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and intercept the resulting request.
2. Make a note of the value of the CSRF token, then drop the request.
3. Open a private/incognito browser window, log in to your other account, and send the update email request into Burp Repeater.
4. Observe that if you swap the CSRF token with the value from the other account, then the request is accepted.
5. Create and host a proof of concept exploit as described in the solution to the CSRF vulnerability with no defenses lab. Note that the CSRF tokens are single-use, so you'll need to include a fresh one.
6. Store the exploit, then click "Deliver to victim" to solve the lab.