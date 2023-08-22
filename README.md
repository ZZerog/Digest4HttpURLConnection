# HttpUrlDigestImpl


Implementation of the Digest Authentication (RFC 2617) through HttpURLConnection.
The HttpURLConnection is the basic Java class for HTTP communication and is useful for simple Http request.
If you need the Digest authentication and use the HttpURLConnection try this simple library.

 * no external dependencies.
 * single class (copy-paste to your project is possible).
 * java9

### Why use Digest in 2023, is old and insecure?
Right, true but some devices (e.g. IP video cameras) still use Digest or Basic authentication :/

### How to use:
1. send request to Http server (e.g. IP video camera)
```
HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
connection.setRequestMethod("GET");
connection.connect();
```

2. Server return 401 Unauthorized with header WWW-Authenticate: Digest ...

3. Call library
```
HttpUrlConnection con = HttpUrlDigestImpl.tryAuth(HttpURLConnection connection, userName, userPassword)
```

4. If response code is 200 (OK) you are authenticated.

or try look at Example.java

### Which type of the Digest authentication is supported?
 * MD5
 * MD5-sess
 * SHA-256
 * SHA-256-sess

### Where to find how Digest work and how to implement it?
 * https://en.wikipedia.org/wiki/Digest_access_authentication

### How to test?
 * Nice project for testing is http://httpbin.org/
    
   


