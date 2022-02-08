<!-- omit in toc -->
# CSRF

<!-- omit in toc -->
## Table of Contents

- [CSRF vulnerability with no defenses](#csrf-vulnerability-with-no-defenses)
- [CSRF where token validation depends on request method](#csrf-where-token-validation-depends-on-request-method)
- [CSRF where token validation depends on token being present](#csrf-where-token-validation-depends-on-token-being-present)
- [CSRF where token is not tied to user session](#csrf-where-token-is-not-tied-to-user-session)
- [CSRF where token is tied to non-session cookie](#csrf-where-token-is-tied-to-non-session-cookie)
- [CSRF where token is duplicated in cookie](#csrf-where-token-is-duplicated-in-cookie)
- [CSRF where Referer validation depends on header being present](#csrf-where-referer-validation-depends-on-header-being-present)
- [CSRF with broken Referer validation](#csrf-with-broken-referer-validation)

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

## CSRF where token is tied to non-session cookie
Reference: https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie

<!-- omit in toc -->
This lab is actually pretty fun. There is a CSRF token protecting the change email functionality, but it is tied to non-session cookie (``csrfKey``). Of course the PoC from the previous lab cannot be used, there is a pretty cool way to inject ``csrfKey`` into the victim's browser. The search functionality stores in a cookie the last searched term, by searching a specific string like the following it is possible to set a valid cookie into the browser:
```
/?search=test%0d%0aSet-Cookie:%20csrfKey=your-key
```

Now that we find a way to inject ``csrfKey`` into the victim's browser the PoC from the previous lab can be used by changing the auto-submit part to: 
```html
<img src="$cookie-injection-url" onerror="document.forms[0].submit()">
```

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that changing the ``session`` cookie logs you out, but changing the ``csrfKey`` cookie merely results in the CSRF token being rejected. This suggests that the ``csrfKey`` cookie may not be strictly tied to the session.
3. Open a private/incognito browser window, log in to your other account, and send a fresh update email request into Burp Repeater.
4. Observe that if you swap the ``csrfKey`` cookie and ``csrf`` parameter from the first account to the second account, the request is accepted.
5. Close the Repeater tab and incognito browser.
6. Back in the original browser, perform a search, send the resulting request to Burp Repeater, and observe that the search term gets reflected in the Set-Cookie header. Since the search function has no CSRF protection, you can use this to inject cookies into the victim user's browser.
7. Create a URL that uses this vulnerability to inject your csrfKey cookie into the victim's browser:
```
/?search=test%0d%0aSet-Cookie:%20csrfKey=your-key
```
8. Create and host a proof of concept exploit as described in the solution to the CSRF vulnerability with no defenses lab, ensuring that you include your CSRF token. The exploit should be created from the email change request.
9. Remove the ``script`` block, and instead add the following code to inject the cookie:
```html
<img src="$cookie-injection-url" onerror="document.forms[0].submit()">
```
10. Store the exploit, then click "Deliver to victim" to solve the lab.

## CSRF where token is duplicated in cookie
Reference: https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie

<!-- omit in toc -->
### Quick Solution
This lab is somehow similar to the one before. In this case the ``csrf`` is duplicated in a cookie and can be injected into the victim's browser the same way as the previous lab.

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that the value of the ``csrf`` body parameter is simply being validated by comparing it with the csrf cookie.
3. Perform a search, send the resulting request to Burp Repeater, and observe that the search term gets reflected in the Set-Cookie header. Since the search function has no CSRF protection, you can use this to inject cookies into the victim user's browser.
4. Create a URL that uses this vulnerability to inject a fake csrf cookie into the victim's browser:
```
/?search=test%0d%0aSet-Cookie:%20csrf=fake
```
5. Create and host a proof of concept exploit as described in the solution to the CSRF vulnerability with no defenses lab, ensuring that your CSRF token is set to "fake". The exploit should be created from the email change request.
6. Remove the script block, and instead add the following code to inject the cookie and submit the form:
```html
<img src="$cookie-injection-url" onerror="document.forms[0].submit();"/>
```
7. Store the exploit, then click "Deliver to victim" to solve the lab.

## CSRF where Referer validation depends on header being present
Reference: https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present

<!-- omit in toc -->
### Quick Solution
This lab has no ``csrf`` token, but using the generated PoC results in a "*Invalid referer header* error. The catch is that removing the **Referer** header solves the issue. To remove it from the POST of the PoC just add the following line in the *head* section of the exploit page:
```html
<meta name="referrer" content="no-referrer">
```

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that if you change the domain in the Referer HTTP header then the request is rejected.
3. Delete the Referer header entirely and observe that the request is now accepted.
4. Create and host a proof of concept exploit as described in the solution to the CSRF vulnerability with no defenses lab. Include the following HTML to suppress the Referer header:
```
<meta name="referrer" content="no-referrer">
```
5. Store the exploit, then click "Deliver to victim" to solve the lab.

## CSRF with broken Referer validation
Reference: https://portswigger.net/web-security/csrf/lab-referer-validation-broken

<!-- omit in toc -->
### Quick Solution
This lab is a little bit different from the previous, in this case the ``Referer`` header cannot be removed, but it can be bypassed by adding a query string to the history of the page:
```javascript
history.pushState("", "", "/?your-lab-id.web-security-academy.net")
```

Modern browsers do not add the query string in the ``Referer`` header, so I had to also add:
```html
<meta name="referrer" content="unsafe-url">
```

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater. Observe that if you change the domain in the Referer HTTP header, the request is rejected.
3. Copy the original domain of your lab instance and append it to the Referer header in the form of a query string. The result should look something like this:
```
Referer: https://arbitrary-incorrect-domain.net?your-lab-id.web-security-academy.net
```
4. Send the request and observe that it is now accepted. The website seems to accept any Referer header as long as it contains the expected domain somewhere in the string.
5. Create a CSRF proof of concept exploit as described in the solution to the CSRF vulnerability with no defenses lab and host it on the exploit server. Edit the JavaScript so that the third argument of the ``history.pushState()`` function includes a query string with your lab instance URL as follows:
```
history.pushState("", "", "/?your-lab-id.web-security-academy.net")
```
This will cause the Referer header in the generated request to contain the URL of the target site in the query string, just like we tested earlier.
6. If you store the exploit and test it by clicking "View exploit", you may encounter the "invalid Referer header" error again. This is because many browsers now strip the query string from the Referer header by default as a security measure. To override this behavior and ensure that the full URL is included in the request, go back to the exploit server and add the following header to the "Head" section:
```
Referrer-Policy: unsafe-url
```
7. Note that unlike the normal Referer header, the word "referrer" must be spelled correctly in this case.
Store the exploit, then click "Deliver to victim" to solve the lab.