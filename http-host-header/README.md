<!-- omit in toc -->
# HTTP Host header

<!-- omit in toc -->
## Table of Contents

- [Basic password reset poisoning](#basic-password-reset-poisoning)
- [Web cache poisoning via ambiguous requests](#web-cache-poisoning-via-ambiguous-requests)
- [Host header authentication bypass](#host-header-authentication-bypass)

## Basic password reset poisoning
Reference: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning

<!-- omit in toc -->
### Quick Solution
Just add the exploit server as the ``Host`` parameter. The user ``carlos`` will click on any link he receives and in this way it is possible to steal his token to reset the password.

<!-- omit in toc -->
### Solution
1. Go to the login page and notice the "Forgot your password?" functionality. Request a password reset for your own account.
2. Go to the exploit server and open the email client. Observe that you have received an email containing a link to reset your password. Notice that the URL contains the query parameter ``temp-forgot-password-token``.
3. Click the link and observe that you are prompted to enter a new password. Reset your password to whatever you want.
4. In Burp, study the HTTP history. Notice that the ``POST /forgot-password`` request is used to trigger the password reset email. This contains the username whose password is being reset as a body parameter. Send this request to Burp Repeater.
5. In Burp Repeater, observe that you can change the Host header to an arbitrary value and still successfully trigger a password reset. Go back to the email server and look at the new email that you've received. Notice that the URL in the email contains your arbitrary Host header instead of the usual domain name.
6. Back in Burp Repeater, change the Host header to your exploit server's domain name (``your-exploit-server-id.web-security-academy.net``) and change the ``username`` parameter to ``carlos``. Send the request.
7. Go to your exploit server and open the access log. You will see a request for ``GET /forgot-password`` with the ``temp-forgot-password-token`` parameter containing Carlos's password reset token. Make a note of this token.
8. Go to your email client and copy the genuine password reset URL from your first email. Visit this URL in your browser, but replace your reset token with the one you obtained from the access log.
9. Change Carlos's password to whatever you want, then log in as carlos to solve the lab.

## Web cache poisoning via ambiguous requests
Reference: https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests

<!-- omit in toc -->
### Quick Solution
Just duplicate the ``Host`` header and the second one gets injected in the webpage.

<!-- omit in toc -->
### Solution
1. Send the ``GET /`` request that received a 200 response to Burp Repeater and study the lab's behavior. Observe that the website validates the Host header. After tampering with it, you are unable to still access the home page.
2. In the original response, notice the verbose caching headers, which tell you when you get a cache hit and how old the cached response is. Add an arbitrary query parameter to your requests to serve as a cache buster, for example, ``GET /?cb=123``. You can simply change this parameter each time you want a fresh response from the back-end server.
3. Notice that if you add a second Host header with an arbitrary value, this appears to be ignored when validating and routing your request. Crucially, notice that the arbitrary value of your second Host header is reflected in an absolute URL used to import a script from ``/resources/js/tracking.js``.
4. Remove the second Host header and send the request again using the same cache buster. Notice that you still receive the same cached response containing your injected value.
5. Go to the exploit server and create a file at ``/resources/js/tracking.js`` containing the payload ``alert(document.cookie)``. Store the exploit and copy the domain name for your exploit server.
6. Back in Burp Repeater, add a second Host header containing your exploit server domain name. The request should look something like this:
```
GET /?cb=123 HTTP/1.1
Host: your-lab-id.web-security-academy.net
Host: your exploit-server-id.web-security-academy.net
```
7. Send the request a couple of times until you get a cache hit with your exploit server URL reflected in the response. To simulate the victim, request the page in your browser using the same cache buster in the URL. Make sure that the ``alert()`` fires.
8. In Burp Repeater, remove any cache busters and keep replaying the request until you have re-poisoned the cache. The lab is solved when the victim visits the home page.

## Host header authentication bypass
Reference: https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass

<!-- omit in toc -->
### Solution
1. Send the ``GET /`` request that received a 200 response to Burp Repeater. Notice that you can change the Host header to an arbitrary value and still successfully access the home page.
2. Browse to ``/robots.txt`` and observe that there is an admin panel at ``/admin``.
3. Try and browse to ``/admin``. You do not have access, but notice the error message, which reveals that the panel can be accessed by local users.
4. Send the ``GET /admin`` request to Burp Repeater.
5. In Burp Repeater, change the Host header to ``localhost`` and send the request. Observe that you have now successfully accessed the admin panel, which provides the option to delete different users.
6. Change the request line to ``GET /admin/delete?username=carlos`` and send the request to delete Carlos and solve the lab.