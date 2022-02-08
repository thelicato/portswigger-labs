<!-- omit in toc -->
# DOM-based

<!-- omit in toc -->
## Table of Contents

- [DOM XSS using web messages](#dom-xss-using-web-messages)
- [DOM XSS using web messages and a JavaScript URL](#dom-xss-using-web-messages-and-a-javascript-url)
- [DOM XSS using web messages and JSON.parse](#dom-xss-using-web-messages-and-jsonparse)
- [DOM-based open redirection](#dom-based-open-redirection)
- [DOM-based cookie manipulation](#dom-based-cookie-manipulation)

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

## DOM-based open redirection
Reference: https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection

<!-- omit in toc -->
### Solution
The blog post page contains the following link, which returns to the home page of the blog:
```html
<a href='#' onclick='returnURL' = /url=https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
```
The ``url`` parameter contains an open redirection vulnerability that allows you to change where the "Back to Blog" link takes the user. To solve the lab, construct and visit the following URL, remembering to change the URL to contain your lab ID and your exploit-server ID:
```
https://your-lab-id.web-security-academy.net/post?postId=4&url=https://your-exploit-server-id.web-security-academy.net/
```

## DOM-based cookie manipulation
Reference: https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation

<!-- omit in toc -->
### Solution
1. Notice that the home page uses a client-side cookie called ``lastViewedProduct``, whose value is the URL of the last product page that the user visited.
2. Go to the exploit server and add the following ``iframe`` to the body, remembering to replace ``your-lab-id`` with your lab ID:
```
<iframe src="https://your-lab-id.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://your-lab-id.web-security-academy.net';window.x=1;">
```
3. Store the exploit and deliver it to the victim.
The original source of the ``iframe`` matches the URL of one of the product pages, except there is a JavaScript payload added to the end. When the ``iframe`` loads for the first time, the browser temporarily opens the malicious URL, which is then saved as the value of the ``lastViewedProduct`` cookie. The onload event handler ensures that the victim is then immediately redirected to the home page, unaware that this manipulation ever took place. While the victim's browser has the poisoned cookie saved, loading the home page will cause the payload to execute.