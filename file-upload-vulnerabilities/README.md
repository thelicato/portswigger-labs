# File Upload Vulnerabilities

## Remote code execution via web shell upload
Reference: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload

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