<!-- omit in toc -->
# CSRF

<!-- omit in toc -->
## Table of Contents

- [CSRF vulnerability with no defenses](#csrf-vulnerability-with-no-defenses)

## CSRF vulnerability with no defenses
Reference: https://portswigger.net/web-security/csrf/lab-no-defenses

<!-- omit in toc -->
### Quick Solution
Just use the PoC generator of Burp and place it in the exploit server. It just works.

<!-- omit in toc -->
### Solution
1. With your browser proxying traffic through Burp Suite, log in to your account, submit the "Update email" form, and find the resulting request in your Proxy history.
2. If you're using Burp Suite Professional, right-click on the request and select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
Alternatively, if you're using Burp Suite Community Edition, use the following HTML template and fill in the request's method, URL, and body parameters. You can get the request URL by right-clicking and selecting "Copy URL".
```html
<form method="$method" action="$url">
     <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
      document.forms[0].submit();
</script>
```
3. Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
4. To verify that the exploit works, try it on yourself by clicking "View exploit" and then check the resulting HTTP request and response.
5. Click "Deliver to victim" to solve the lab.