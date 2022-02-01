<!-- omit in toc -->
# SQL Injection

<!-- omit in toc -->
## Table of Contents

- [SQL injection UNION attack, determining the number of columns returned by the query](#sql-injection-union-attack-determining-the-number-of-columns-returned-by-the-query)

## SQL injection UNION attack, determining the number of columns returned by the query
Reference: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

<!-- omit in toc -->
### Quick Solution
The ``category`` parameter is vulnerable to XSS, use a **UNION** attack to retrieve the number of columns, the payload is simply:
```
# Keep adding NULL until the error disappears
'+UNION+SELECT+NULL,NULL--
```
<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Modify the ``category`` parameter, giving it the value ``'+UNION+SELECT+NULL--``. Observe that an error occurs.
3. Modify the category parameter to add an additional column containing a null value: 
```
'+UNION+SELECT+NULL,NULL--
```
4. Continue adding null values until the error disappears and the response includes additional content containing the null values.