<!-- omit in toc -->
# DOM-based

<!-- omit in toc -->
## Table of Contents

- [DOM XSS using web messages](#dom-xss-using-web-messages)
- [DOM XSS using web messages and a JavaScript URL](#dom-xss-using-web-messages-and-a-javascript-url)

## DOM XSS using web messages
Reference: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages

<!-- omit in toc -->
### Solution
1. Notice that the home page contains an ``addEventListener()`` call that listens for a web message.
2. Go to the exploit server and add the following iframe to the body. Remember to add your own lab ID:
```html
<iframe src="https://your-lab-id.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
3. Store the exploit and deliver it to the victim.
When the iframe loads, the ``postMessage()`` method sends a web message to the home page. The event listener, which is intended to serve ads, takes the content of the web message and inserts it into the ``div`` with the ID ``ads``. However, in this case it inserts our ``img`` tag, which contains an invalid ``src`` attribute. This throws an error, which causes the ``onerror`` event handler to execute our payload.

## DOM XSS using web messages and a JavaScript URL
Reference: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url

<!-- omit in toc -->
### Solution
1. Notice that the home page contains an ``addEventListener()`` call that listens for a web message. The JavaScript contains a flawed ``indexOf()`` check that looks for the strings "``http:``" or "``https:``" anywhere within the web message. It also contains the sink ``location.href``.
2. Go to the exploit server and add the following ``iframe`` to the body, remembering to replace ``your-lab-id`` with your lab ID:
```html
<iframe src="https://your-lab-id.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```
3. Store the exploit and deliver it to the victim.
This script sends a web message containing an arbitrary JavaScript payload, along with the string "``http:``". The second argument specifies that any ``targetOrigin`` is allowed for the web message.

When the iframe loads, the ``postMessage()`` method sends the JavaScript payload to the main page. The event listener spots the ``"http:``" string and proceeds to send the payload to the ``location.href`` sink, where the ``print()`` function is called.