<!-- omit in toc -->
# File Upload Vulnerabilities

<!-- omit in toc -->
## Table of Contents

- [Remote code execution via web shell upload](#remote-code-execution-via-web-shell-upload)
- [Web shell upload via Content-Type restriction bypass](#web-shell-upload-via-content-type-restriction-bypass)
- [Web shell upload via path traversal](#web-shell-upload-via-path-traversal)
- [Web shell upload via extension blacklist bypass](#web-shell-upload-via-extension-blacklist-bypass)
- [Web shell upload via obfuscated file extension](#web-shell-upload-via-obfuscated-file-extension)
- [Remote code execution via polyglot web shell upload](#remote-code-execution-via-polyglot-web-shell-upload)

## Remote code execution via web shell upload
Reference: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload

<!-- omit in toc -->
### Quick Solution
Upload the file as it is.

<!-- omit in toc -->
### Solution

1. While proxying traffic through Burp, log in to your account and notice the option for uploading an avatar image.
2. Upload an arbitrary image, then return to your account page. Notice that a preview of your avatar is now displayed on the page.
3. In Burp, go to Proxy > HTTP history. Click the filter bar to open the Filter settings dialog. Under Filter by MIME type, enable the Images checkbox, then apply your changes.
4. In the proxy history, notice that your image was fetched using a ``GET`` request to ``/files/avatars/<YOUR-IMAGE>``. Send this request to Burp Repeater.
5. On your system, create a file called exploit.php, containing a script for fetching the contents of Carlos's secret file. For example:
```
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
6. Use the avatar upload function to upload your malicious PHP file. The message in the response confirms that this was uploaded successfully.
7. In Burp Repeater, change the path of the request to point to your PHP file:
```
GET /files/avatars/exploit.php HTTP/1.1
```
8. Send the request. Notice that the server has executed your script and returned its output (Carlos's secret) in the response.
Submit the secret to solve the lab.

## Web shell upload via Content-Type restriction bypass

Reference: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass

<!-- omit in toc -->
### Quick Solution
Change the ``Content-Type`` to ``image/jpeg`` or ``image/png`` during the POST request.

<!-- omit in toc -->
### Solution

1. Log in and upload an image as your avatar, then go back to your account page. 
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a ``GET`` request to ``/files/avatars/<YOUR-IMAGE>``. Send this request to Burp Repeater. 
3. On your system, create a file called ``exploit.php``, containing a script for fetching the contents of Carlos's secret. For example:
```
 <?php echo file_get_contents('/home/carlos/secret'); ?> 
```
4. Attempt to upload this script as your avatar. The response indicates that you are only allowed to upload files with the MIME type ``image/jpeg`` or ``image/png``.
5. In Burp, go back to the proxy history and find the ``POST /my-account/avatar`` request that was used to submit the file upload. Send this to Burp Repeater. 
6. In Burp Repeater, go to the tab containing the ``POST /my-account/avatar`` request. In the part of the message body related to your file, change the specified ``Content-Type`` to ``image/jpeg``.
7. Send the request. Observe that the response indicates that your file was successfully uploaded.
8. Switch to the other Repeater tab containing the ``GET /files/avatars/<YOUR-IMAGE>`` request. In the path, replace the name of your image file with ``exploit.php`` and send the request. Observe that Carlos's secret was returned in the response. 
9. Submit the secret to solve the lab.

## Web shell upload via path traversal

Reference: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal

<!-- omit in toc -->
### Quick Solution
Add a path traversal while uploading the avatar to reach a higher level directory. The basic path traversal is blocked, so the **slash** must be encoded as *%2F*.

<!-- omit in toc -->
### Solution

1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to Proxy > HTTP history and notice that your image was fetched using a GET request to /files/avatars/<YOUR-IMAGE>. Send this request to Burp Repeater.
3. On your system, create a file called exploit.php, containing a script for fetching the contents of Carlos's secret. For example:
```   
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
4. Upload this script as your avatar. Notice that the website doesn't seem to prevent you from uploading PHP files.
5. In Burp Repeater, go to the tab containing the GET /files/avatars/<YOUR-IMAGE> request. In the path, replace the name of your image file with exploit.php and send the request. Observe that instead of executing the script and returning the output, the server has just returned the contents of the PHP file as plain text.
6. In Burp's proxy history, find the POST /my-account/avatar request that was used to submit the file upload and send it to Burp Repeater.
7. In Burp Repeater, go to the tab containing the POST /my-account/avatar request and find the part of the request body that relates to your PHP file. In the Content-Disposition header, change the filename to include a directory traversal sequence:
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
8. Send the request. Notice that the response says The file avatars/exploit.php has been uploaded. This suggests that the server is stripping the directory traversal sequence from the file name.
9. Obfuscate the directory traversal sequence by URL encoding the forward slash (/) character, resulting in:
filename="..%2fexploit.php"
10. Send the request and observe that the message now says The file avatars/../exploit.php has been uploaded. This indicates that the file name is being URL decoded by the server.
11. In the browser, go back to your account page.
12. In Burp's proxy history, find the GET /files/avatars/..%2fexploit.php request. Observe that Carlos's secret was returned in the response. This indicates that the file was uploaded to a higher directory in the filesystem hierarchy (/files), and subsequently executed by the server. Note that this means you can also request this file using GET /files/exploit.php.
13. Submit the secret to solve the lab.

## Web shell upload via extension blacklist bypass

Reference: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass

<!-- omit in toc -->
### Quick Solution
**THIS SOLUTION IS DIFFERENT FROM THE ONE IN THE 'Solution' SECTION**. Just change the extension of the payload from *.php* to *.phtml*.

<!-- omit in toc -->
### Solution

1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a ``GET`` request to ``/files/avatars/<YOUR-IMAGE>``. Send this request to Burp Repeater.
3. On your system, create a file called ``exploit.php`` containing a script for fetching the contents of Carlos's secret. For example:
```
<?php echo file_get_contents('/home/carlos/secret'); ?> 
```
4. Attempt to upload this script as your avatar. The response indicates that you are not allowed to upload files with a ``.php`` extension. 
5. In Burp's proxy history, find the ``POST /my-account/avatar`` request that was used to submit the file upload. In the response, notice that the headers reveal that you're talking to an Apache server. Send this request to Burp Repeater.
6. In Burp Repeater, go to the tab for the ``POST /my-account/avatar`` request and find the part of the body that relates to your PHP file. Make the following changes:
    - Change the value of the ``filename`` parameter to ``.htaccess``.
    - Change the value of the ``Content-Type`` header to ``text/plain``.
    - Replace the contents of the file (your PHP payload) with the following Apache directive: ``AddType application/x-httpd-php .l33t``
      This maps an arbitrary extension (``.l33t``) to the executable MIME type`` application/x-httpd-php``. As the server uses the mod_php module, it knows how to handle this already.
7. Send the request and observe that the file was successfully uploaded. 
8. Use the back arrow in Burp Repeater to return to the original request for uploading your PHP exploit. 
9. Change the value of the ``filename`` parameter from ``exploit.php`` to ``exploit.l33t``. Send the request again and notice that the file was uploaded successfully.
10. Switch to the other Repeater tab containing the ``GET /files/avatars/<YOUR-IMAGE>`` request. In the path, replace the name of your image file with ``exploit.l33t`` and send the request. Observe that Carlos's secret was returned in the response. Thanks to our malicious ``.htaccess`` file, the ``.l33t`` file was executed as if it were a ``.php`` file.
11. Submit the secret to solve the lab. 

## Web shell upload via obfuscated file extension

Reference: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension

<!-- omit in toc -->
### Quick Solution
Only **png** and **jpg** extensions are allowed. Just change the ``filename`` extension from ``.php`` to ``.php%00.png`` or ``.php%00.jpg``.

<!-- omit in toc -->
### Solution

1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a ``GET`` request to ``/files/avatars/<YOUR-IMAGE>``.
3. Send this request to Burp Repeater. On your system, create a file called ``exploit.php``, containing a script for fetching the contents of Carlos's secret. For example:
```
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
4. Attempt to upload this script as your avatar. The response indicates that you are only allowed to upload JPG and PNG files.
5. In Burp's proxy history, find the ``POST /my-account/avatar`` request that was used to submit the file upload. Send this to Burp Repeater.
6. In Burp Repeater, go to the tab for the ``POST /my-account/avatar`` request and find the part of the body that relates to your PHP file. In the ``Content-Disposition`` header, change the value of the ``filename`` parameter to include a URL encoded null byte, followed by the ``.jpg`` extension:
``filename="exploit.php%00.jpg"``
7. Send the request and observe that the file was successfully uploaded. Notice that the message refers to the file as ``exploit.php``, suggesting that the null byte and ``.jpg`` extension have been stripped. 
8. Switch to the other Repeater tab containing the ``GET /files/avatars/<YOUR-IMAGE>`` request. In the path, replace the name of your image file with ``exploit.php`` and send the request. Observe that Carlos's secret was returned in the response.
9. Submit the secret to solve the lab. 

## Remote code execution via polyglot web shell upload
Reference: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload

<!-- omit in toc -->
### Quick Solution
Use ``ExifTool`` to add PHP code inside the **Comment** section of a valid image. ``ExifTool`` has been dockerized by [RAUDI](https://github.com/cybersecsi/RAUDI). Here is the command that has been executed (from the ``exploits`` directory) to create the ``polyglot.php`` file:
```
docker run -it --rm -v $pwd/:/content secsi/exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" /content/dont-panic.jpg -o /content/polyglot.php
```

<!-- omit in toc -->
### Solution

1. On your system, create a file called ``exploit.php`` containing a script for fetching the contents of Carlos's secret. For example:
```
<?php echo file_get_contents('/home/carlos/secret'); ?> 
```
2. Log in and attempt to upload the script as your avatar. Observe that the server successfully blocks you from uploading files that aren't images, even if you try using some of the techniques you've learned in previous labs.
3. Create a polyglot PHP/JPG file that is fundamentally a normal image, but contains your PHP payload in its metadata. A simple way of doing this is to download and run ExifTool from the command line as follows:
```
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```
This adds your PHP payload to the image's Comment field, then saves the image with a ``.php`` extension. 
4. In your browser, upload the polyglot image as your avatar, then go back to your account page. 
5. In Burp's proxy history, find the ``GET /files/avatars/polyglot.php`` request. Use the message editor's search feature to find the ``START`` string somewhere within the binary image data in the response. Between this and the ``END`` string, you should see Carlos's secret, for example:
``START 2B2tlPyJQfJDynyKME5D02Cw0ouydMpZ END``
6. Submit the secret to solve the lab. 

