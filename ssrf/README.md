<!-- omit in toc -->
# SSRF

<!-- omit in toc -->
## Table of Contents

- [Basic SSRF against the local server](#basic-ssrf-against-the-local-server)
- [Basic SSRF against another back-end system](#basic-ssrf-against-another-back-end-system)
- [SSRF with blacklist-based input filter](#ssrf-with-blacklist-based-input-filter)
- [SSRF with filter bypass via open redirection vulnerability](#ssrf-with-filter-bypass-via-open-redirection-vulnerability)
- [Blind SSRF with out-of-band detection](#blind-ssrf-with-out-of-band-detection)

## Basic SSRF against the local server
Reference: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

<!-- omit in toc -->
### Solution
1. Browse to ``/admin`` and observe that you can't directly access the admin page.
2. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Change the URL in the ``stockApi`` parameter to ``http://localhost/admin``. This should display the administration interface.
4. Read the HTML to identify the URL to delete the target user, which is:
```
http://localhost/admin/delete?username=carlos
```
5. Submit this URL in the ``stockApi`` parameter, to deliver the SSRF attack.

## Basic SSRF against another back-end system
Reference: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

<!-- omit in toc -->
### Solution
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Intruder.
2. Click "Clear §", change the ``stockApi`` parameter to ``http://192.168.0.1:8080/admin`` then highlight the final octet of the IP address (the number 1), click "Add §".
3. Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
4. Click "Start attack".
5. Click on the "Status" column to sort it by status code ascending. You should see a single entry with a status of 200, showing an admin interface.
6. Click on this request, send it to Burp Repeater, and change the path in the ``stockApi`` to: ``/admin/delete?username=carlos``

## SSRF with blacklist-based input filter
Reference: https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter

<!-- omit in toc -->
### Solution
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the ``stockApi`` parameter to ``http://127.0.0.1/`` and observe that the request is blocked.
3. Bypass the block by changing the URL to: ``http://127.1/``
4. Change the URL to ``http://127.1/admin`` and observe that the URL is blocked again.
5. Obfuscate the "a" by double-URL encoding it to ``%2561`` to access the admin interface and delete the target user.

## SSRF with filter bypass via open redirection vulnerability
Reference: https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection

<!-- omit in toc -->
### Solution
1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Try tampering with the ``stockApi`` parameter and observe that it isn't possible to make the server issue the request directly to a different host.
3. Click "next product" and observe that the ``path`` parameter is placed into the Location header of a redirection response, resulting in an open redirection.
4. Create a URL that exploits the open redirection vulnerability, and redirects to the admin interface, and feed this into the ``stockApi`` parameter on the stock checker:
```
/product/nextProduct?path=http://192.168.0.12:8080/admin
```
5. Observe that the stock checker follows the redirection and shows you the admin page.
6. Amend the path to delete the target user:
```
/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

## Blind SSRF with out-of-band detection
Reference: https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection

<!-- omit in toc -->
### Solution
1. In Burp Suite Professional, go to the Burp menu and launch the Burp Collaborator client.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
3. Visit a product, intercept the request in Burp Suite, and send it to Burp Repeater.
4. Change the Referer header to use the generated Burp Collaborator domain in place of the original domain. Send the request.
5. Go back to the Burp Collaborator client window, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
6. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.