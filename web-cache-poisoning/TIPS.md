# Tips for Web Cache Poisoning


### Unkeyed headers
Here is a list of interesting headers to check (single or grouped):

```
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Scheme
X-Host
```
## Display cache key
You can try to use  the following headers to display the cache key in the response:

```
Pragma: x-get-cache-key
Pragma: akamai-x-get-cache-key
```

## Exploiting cache key flaws
Here is a list of some typical cache key flaws:
- Unkeyed port
- Unkeyed query string
- Unkeyed query parameters (check for UTM parameters like ``utm_content``)
- Cache paramter cloaking
- Cache key injection
- Internal cache poisoning