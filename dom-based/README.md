<!-- omit in toc -->
# DOM-based

<!-- omit in toc -->
## Table of Contents

- [DOM XSS using web messages](#dom-xss-using-web-messages)
- [DOM XSS using web messages and a JavaScript URL](#dom-xss-using-web-messages-and-a-javascript-url)
- [DOM XSS using web messages and JSON.parse](#dom-xss-using-web-messages-and-jsonparse)

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

## DOM XSS using web messages and JSON.parse
Reference: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse

<!-- omit in toc -->
### Solution
1. Notice that the home page contains an event listener that listens for a web message. This event listener expects a string that is parsed using ``JSON.parse()``. In the JavaScript, we can see that the event listener expects a ``type`` property and that the ``load-channel`` case of the ``switch`` statement changes the ``iframe src`` attribute.
2. Go to the exploit server and add the following ``iframe`` to the body, remembering to replace ``your-lab-id`` with your lab ID:
```html
<iframe src=https://your-lab-id.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```
3. Store the exploit and deliver it to the victim.
   
When the iframe we constructed loads, the ``postMessage()`` method sends a web message to the home page with the type ``load-channel``. The event listener receives the message and parses it using ``JSON.parse()`` before sending it to the switch.

The switch triggers the ``load-channel`` case, which assigns the ``url`` property of the message to the ``src`` attribute of the ``ACMEplayer.element iframe``. However, in this case, the ``url`` property of the message actually contains our JavaScript payload.

As the second argument specifies that any ``targetOrigin`` is allowed for the web message, and the event handler does not contain any form of origin check, the payload is set as the ``src`` of the ``ACMEplayer.element iframe``. The ``print()`` function is called when the victim loads the page in their browser.