<!-- omit in toc -->
# OS command injection

<!-- omit in toc -->
## Table of Contents

- [OS command injection, simple case](#os-command-injection-simple-case)

## OS command injection, simple case
Reference: https://portswigger.net/web-security/os-command-injection/lab-simple

<!-- omit in toc -->
### Quick Solution
Intercept the **check stock** request and modify the ``storeId`` parameter to:
```
%26whoami%26
```
The payload provided by PortSwigger is a little bit different, but the result is the same.

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify a request that checks the stock level.
2. Modify the ``storeID`` parameter, giving it the value ``1|whoami``.
3. Observe that the response contains the name of the current user.