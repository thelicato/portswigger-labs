<!-- omit in toc -->
# Business-logic

<!-- omit in toc -->
## Table of Contents

- [Excessive trust in client-side controls](#excessive-trust-in-client-side-controls)
- [High-level logic vulnerability](#high-level-logic-vulnerability)

## Excessive trust in client-side controls
Reference: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls

<!-- omit in toc -->
### Solution
1. With Burp running, log in and attempt to buy the leather jacket. The order is rejected because you don't have enough store credit.
2. In Burp, go to "Proxy" > "HTTP history" and study the order process. Notice that when you add an item to your cart, the corresponding request contains a ``price`` parameter. Send the ``POST /cart`` request to Burp Repeater.
3. In Burp Repeater, change the price to an arbitrary integer and send the request. Refresh the cart and confirm that the price has changed based on your input.
4. Repeat this process to set the price to any amount less than your available store credit.
5. Complete the order to solve the lab.

## High-level logic vulnerability
Reference: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level

<!-- omit in toc -->
### Solution
1. With Burp running, log in and add a cheap item to your cart.
2. In Burp, go to "Proxy" > "HTTP history" and study the corresponding HTTP messages. Notice that the quantity is determined by a parameter in the ``POST /cart`` request.
3. Go to the "Intercept" tab and turn on interception. Add another item to your cart and go to the intercepted ``POST /cart`` request in Burp.
4. Change the ``quantity`` parameter to an arbitrary integer, then forward any remaining requests. Observe that the quantity in the cart was successfully updated based on your input.
5. Repeat this process, but request a negative quantity this time. Check that this is successfully deducted from the cart quantity.
6. Request a suitable negative quantity to remove more units from the cart than it currently contains. Confirm that you have successfully forced the cart to contain a negative quantity of the product. Go to your cart and notice that the total price is now also a negative amount.
7. Add the leather jacket to your cart as normal. Add a suitable negative quantity of the another item to reduce the total price to less than your remaining store credit.
8. Place the order to solve the lab.