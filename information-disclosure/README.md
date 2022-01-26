<!-- omit in toc -->
# Information Disclosure

<!-- omit in toc -->
## Table of Contents

- [Information disclosure in error messages](#information-disclosure-in-error-messages)

## Information disclosure in error messages
Reference: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages

<!-- omit in toc -->
### Quick Solution
Go the one of the products page and change the ``productId`` parameter value to some random string.

<!-- omit in toc -->
### Solution
1. With Burp running, open one of the product pages.
2. In Burp, go to "Proxy" > "HTTP history" and notice that the ``GET`` request for product pages contains a ``productID`` parameter. Send the ``GET /product?productId=1`` request to Burp Repeater. Note that your ``productId`` might be different depending on which product page you loaded.
3. In Burp Repeater, change the value of the ``productId`` parameter to a non-integer data type, such as a string. Send the request.
``GET /product?productId="example"``
4. The unexpected data type causes an exception, and a full stack trace is displayed in the response. This reveals that the lab is using Apache Struts 2 2.3.31.
5. Go back to the lab, click "Submit solution", and enter **2 2.3.31** to solve the lab.


