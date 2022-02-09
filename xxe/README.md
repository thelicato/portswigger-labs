<!-- omit in toc -->
# XXE

<!-- omit in toc -->
## Table of Contents

- [Exploiting XXE using external entities to retrieve files](#exploiting-xxe-using-external-entities-to-retrieve-files)

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