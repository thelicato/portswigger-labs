<!-- omit in toc -->
# DOM-based

<!-- omit in toc -->
## Table of Contents

- [DOM XSS using web messages](#dom-xss-using-web-messages)

## DOM XSS using web messages
Reference: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages

<!-- omit in toc -->
### Solution
1. Notice that the home page contains an ``addEventListener()`` call that listens for a web message.
2. Go to the exploit server and add the following iframe to the body. Remember to add your own lab ID:
```
<iframe src="https://your-lab-id.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
3. Store the exploit and deliver it to the victim.
When the iframe loads, the ``postMessage()`` method sends a web message to the home page. The event listener, which is intended to serve ads, takes the content of the web message and inserts it into the ``div`` with the ID ``ads``. However, in this case it inserts our ``img`` tag, which contains an invalid ``src`` attribute. This throws an error, which causes the ``onerror`` event handler to execute our payload.