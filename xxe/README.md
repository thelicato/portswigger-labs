<!-- omit in toc -->
# XXE

<!-- omit in toc -->
## Table of Contents

- [Exploiting XXE using external entities to retrieve files](#exploiting-xxe-using-external-entities-to-retrieve-files)
- [Exploiting XXE to perform SSRF attacks](#exploiting-xxe-to-perform-ssrf-attacks)

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