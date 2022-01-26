<!-- omit in toc -->
# Information Disclosure

<!-- omit in toc -->
## Table of Contents

- [Information disclosure in error messages](#information-disclosure-in-error-messages)
- [Information disclosure on debug page](#information-disclosure-on-debug-page)
- [Information disclosure via backup files](#information-disclosure-via-backup-files)
- [Authentication bypass via information disclosure](#authentication-bypass-via-information-disclosure)
- [Information disclosure in version control history](#information-disclosure-in-version-control-history)

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

## Information disclosure on debug page
Reference: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page

<!-- omit in toc -->
### Quick Solution
Find a comment that points to ``/cgi-bing/phpinfo.php``. Go to the page and find the ``SECRET_KEY`` environment variable value.

<!-- omit in toc -->
### Solution
1. With Burp running, browse to the home page.
2. Go to the "Target" > "Site Map" tab. Right-click on the top-level entry for the lab and select "Engagement tools" > "Find comments". Notice that the home page contains an HTML comment that contains a link called "Debug". This points to ``/cgi-bin/phpinfo.php``.
3. In the site map, right-click on the entry for ``/cgi-bin/phpinfo.php`` and select "Send to Repeater".
4. In Burp Repeater, send the request to retrieve the file. Notice that it reveals various debugging information, including the ``SECRET_KEY`` environment variable.
5. Go back to the lab, click "Submit solution", and enter the ``SECRET_KEY`` to solve the lab.

## Information disclosure via backup files
Reference: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files

<!-- omit in toc -->
### Quick Solution
Browse to ``/robots.txt`` and discover that a ``/backup`` folder exists. Browse to ``/backup`` and then to the ``ProductTemplate.java.bak`` file which contains the hard-coded password.

<!-- omit in toc -->
### Solution
1. Browse to ``/robots.txt`` and notice that it reveals the existence of a ``/backup`` directory. Browse to ``/backup`` to find the file ``ProductTemplate.java.bak``. Alternatively, right-click on the lab in the site map and go to "Engagement tools" > "Discover content". Then, launch a content discovery session to discover the ``/backup`` directory and its contents.
2. Browse to ``/backup/ProductTemplate.java.bak`` to access the source code.
3. In the source code, notice that the connection builder contains the hard-coded password for a Postgres database.
4. Go back to the lab, click "Submit solution", and enter the database password to solve the lab.

## Authentication bypass via information disclosure
Reference: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass

<!-- omit in toc -->
### Quick Solution
Browse to ``/admin`` and discover that it is not available to low-privileges users. Use the ``TRACE`` method to discover that the ``X-Custom-IP-Authorization`` header is appended to the response with your IP address. Change the value of this header to ``127.0.0.1`` and now you can access the ``/admin`` page.

<!-- omit in toc -->
### Solution
1. In Burp Repeater, browse to ``GET /admin``. The response discloses that the admin panel is only accessible if logged in as an administrator, or if requested from a local IP.
2. Send the request again, but this time use the `TRACE` method:
``TRACE /admin``
3. Study the response. Notice that the ``X-Custom-IP-Authorization`` header, containing your IP address, was automatically appended to your request. This is used to determine whether or not the request came from the ``localhost`` IP address.
4. Go to "Proxy" > "Options", scroll down to the "Match and Replace" section, and click "Add". Leave the match condition blank, but in the "Replace" field, enter ``X-Custom-IP-Authorization: 127.0.0.1``. Burp Proxy will now add this header to every request you send.
5. Browse to the home page. Notice that you now have access to the admin panel, where you can delete Carlos.

## Information disclosure in version control history
Reference: https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history

<!-- omit in toc -->
### Quick Solution
Browse to ``/.git``, download the folder with ``wget``. Study the commits and discover that there is a commit called ``Remove admin password from config``. Look at the diff and retrieve the hardcoded password.

<!-- omit in toc -->
### Solution
1. Open the lab and browse to ``/.git`` to reveal the lab's Git version control data.
2. Download a copy of this entire directory. For non-Windows users, the easiest way to do this is using the command ``wget -r https://your-lab-id.web-security-academy.net/.git``. Windows users will need to find an alternative method, or install a UNIX-like environment, such as Cygwin, in order to use this command.
3. Explore the downloaded directory using your local Git installation. Notice that there is a commit with the message "``Remove admin password from config``".
4. Look closer at the diff for the changed ``admin.conf`` file. Notice that the commit replaced the hard-coded admin password with an environment variable ``ADMIN_PASSWORD`` instead. However, the hard-coded password is still clearly visible in the diff.
5. Go back to the lab and log in to the administrator account using the leaked password.
6. To solve the lab, open the admin interface and delete Carlos's account.