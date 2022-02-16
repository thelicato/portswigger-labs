<!-- omit in toc -->
# Business-logic

<!-- omit in toc -->
## Table of Contents

- [Excessive trust in client-side controls](#excessive-trust-in-client-side-controls)
- [High-level logic vulnerability](#high-level-logic-vulnerability)
- [Low-level logic flaw](#low-level-logic-flaw)

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

## Low-level logic flaw
Reference: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level

<!-- omit in toc -->
### Quick Solution
This one is a little bit tricky. Once you add a **huge** number of *leather jackets* the price value becomes a huge negative number and then it keeps raising until it reaches a value near zero. Add some other product to reach a price between 0 and 100 and you are done!

<!-- omit in toc -->
### Solution
1. With Burp running, log in and attempt to buy the leather jacket. The order is rejected because you don't have enough store credit. In the proxy history, study the order process. Send the ``POST /cart`` request to Burp Repeater.
2. In Burp Repeater, notice that you can only add a 2-digit quantity with each request. Send the request to Burp Intruder.
3. Go to Burp Intruder. On the "Positions" tab, clear all the default payload positions and set the ``quantity`` parameter to 99.
4. On the "Payloads" tab, select the payload type "Null payloads". Under "Payload options", select "Continue indefinitely". Start the attack.
5. While the attack is running, go to your cart. Keep refreshing the page every so often and monitor the total price. Eventually, notice that the price suddenly switches to a large negative integer and starts counting up towards 0. The price has exceeded the maximum value permitted for an integer in the back-end programming language (2,147,483,647). As a result, the value has looped back around to the minimum possible value (-2,147,483,648).
6. Clear your cart. In the next few steps, we'll try to add enough units so that the price loops back around and settles between $0 and the $100 of your remaining store credit. This is not mathematically possible using only the leather jacket.
7. Create the same Intruder attack again, but this time, under "Payloads" > "Payload Options", choose to generate exactly 323 payloads.
8. Go to the "Resource pool" tab and add the attack to a resource pool with the "Maximum concurrent requests" set to 1. Start the attack.
9. When the Intruder attack finishes, go to the ``POST /cart`` request in Burp Repeater and send a single request for 47 jackets. The total price of the order should now be ``-$1221.96``.
10. Use Burp Repeater to add a suitable quantity of another item to your cart so that the total falls between $0 and $100.
11. Place the order to solve the lab.