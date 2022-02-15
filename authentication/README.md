<!-- omit in toc -->
# Authentication

<!-- omit in toc -->
## Table of Contents

- [Username enumeration via different responses](#username-enumeration-via-different-responses)
- [Username enumeration via subtly different responses](#username-enumeration-via-subtly-different-responses)

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