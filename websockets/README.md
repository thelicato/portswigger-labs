<!-- omit in toc -->
# WebSockets

<!-- omit in toc -->
## Table of Contents

- [Manipulating WebSocket messages to exploit vulnerabilities](#manipulating-websocket-messages-to-exploit-vulnerabilities)
- [Manipulating the WebSocket handshake to exploit vulnerabilities](#manipulating-the-websocket-handshake-to-exploit-vulnerabilities)
- [Cross-site WebSocket hijacking](#cross-site-websocket-hijacking)

## Manipulating WebSocket messages to exploit vulnerabilities
Reference: https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities

<!-- omit in toc -->
## Quick Solution 
Intercept the WebSocket message and set the content to ``<img src=x onerror='alert(1)'>``.

<!-- omit in toc -->
## Solution 
1. Click "Live chat" and send a chat message. 
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Using your browser, send a new message containing a < character. In Burp Proxy, find the corresponding WebSocket message and observe that the < has been HTML-encoded by the client before sending.
4. Ensure that Burp Proxy is configured to intercept WebSocket messages, then send another chat message.
5. Edit the intercepted message to contain the following payload: ``<img src=1 onerror='alert(1)'>``
6. Observe that an alert is triggered in your browser. This will also happen in the support agent's browser. 

## Manipulating the WebSocket handshake to exploit vulnerabilities
Reference: https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities

<!-- omit in toc -->
## Quick Solution 
Intercept the WebSocket message and set the content to ``<img src=1 oNeRrOr=alert`1`>`` since there is an aggressive but flawed XSS filter (the solution says to also add the ``X-Forwarded-For: 1.1.1.1`` header to spoof the IP address).

<!-- omit in toc -->
## Solution 
1. Click "Live chat" and send a chat message.
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Right-click on the message and select "Send to Repeater".
4. Edit and resend the message containing a basic XSS payload, such as:
```
<img src=1 onerror='alert(1)'>
```
5. Observe that the attack has been blocked, and that your WebSocket connection has been terminated. 
6. Click "Reconnect", and observe that the connection attempt fails because your IP address has been banned.
7. Add the following header to the handshake request to spoof your IP address:
```
X-Forwarded-For: 1.1.1.1
```
8. Click "Connect" to successfully reconnect the WebSocket. 
9. Send a WebSocket message containing an obfuscated XSS payload, such as:
```
<img src=1 oNeRrOr=alert`1`> 
```

## Cross-site WebSocket hijacking
Reference: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab

<!-- omit in toc -->
## Quick Solution 

<!-- omit in toc -->
## Solution 