<!-- omit in toc -->
# HTTP Host header

<!-- omit in toc -->
## Table of Contents

- [Basic password reset poisoning](#basic-password-reset-poisoning)

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