# Tips for Web Cache Poisoning

Here is a list of interesting headers to check (single or grouped):

```
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Scheme
X-Host
```
## Display cache key

You can use ``Pragma: x-get-cache-key`` header to display the cache key in the response.