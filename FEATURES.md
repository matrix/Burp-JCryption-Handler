# Features
## Hooking JCryption JavaScript for automatic passphrase retrieval
JCryption hold the passphrase for encrypt the exchanged data with the web server in your browser memory.
<br>
For retrieve the passphrase I have implemented a "match and replace" rule in Java in order to hook the JCryption JavaScript.
<br>

The original code is the following :

```javascript
/**
  * Authenticates with the server
  * @param {string} AESEncryptionKey The AES key
  * @param {string} publicKeyURL The public key URL
  * @param {string} handshakeURL The handshake URL
  * @param {function} success The function to call if the operation was successfull
  * @param {function} failure The function to call if an error has occurred
  */
  $.jCryption.authenticate = function(AESEncryptionKey, publicKeyURL, handshakeURL, success, failure) {
    $.jCryption.getPublicKey(publicKeyURL, function() {
      $.jCryption.encryptKey(AESEncryptionKey, function(encryptedKey) {
        $.jCryption.handshake(handshakeURL, encryptedKey, function(response) {
          if ($.jCryption.challenge(response.challenge, AESEncryptionKey)) {
            success.call(this, AESEncryptionKey);
          } else {
            failure.call(this);
          }
        });
      });
    });
  };
```

I replace the "success.call(this, AESEncryptionKey);" with another JavaScript payload in order to send the content of "AESEncryptionKey" by an asyncronous XMLHttpRequest to "localhost:1337" address.

That is the modified code :

```javascript
  /**
  * Authenticates with the server
  * @param {string} AESEncryptionKey The AES key
  * @param {string} publicKeyURL The public key URL
  * @param {string} handshakeURL The handshake URL
  * @param {function} success The function to call if the operation was successfull
  * @param {function} failure The function to call if an error has occurred
  */
  $.jCryption.authenticate = function(AESEncryptionKey, publicKeyURL, handshakeURL, success, failure) {
    $.jCryption.getPublicKey(publicKeyURL, function() {
      $.jCryption.encryptKey(AESEncryptionKey, function(encryptedKey) {
        $.jCryption.handshake(handshakeURL, encryptedKey, function(response) {
          if ($.jCryption.challenge(response.challenge, AESEncryptionKey)) {
            setTimeout(function(){ success.call(this, AESEncryptionKey); }, 888); var x = new XMLHttpRequest(); x.open("GET", "https://localhost:1337/?p="+AESEncryptionKey, true); x.send();
          } else {
            failure.call(this);
          }
        });
      });
    });
  };
```

Note that the "setTimeout" is to delay the "success.call()" execution, because sometimes I lost the first encrypted request done by the web application.
<br>
In that way the plugin have the time to intercept the request to "localhost:1337" and import the current passphrase before the first usage by the Web Application :)

## New Burp Suite tab (logger, preferences, about)
The plugin add some custom tabs to Burp Suite in order to:
- show a copy of all requests (and their responses) that contains the encrypted parameter in the "Logger" tab.<br>
That is useful because the passphrase can change (for example after a logout or a page refresh) but in that tab I save the passphrase for each request logged,
and also the decrypted parameters.

- setup the plugin by the "Preferences" tab.<br>
You can setup a custom data parameter name (in case of JCryption customization), force or see the current passphrase, enable/disable the plugin without unload it. 

- show the "About" tab.<br>
You can find the link to this project on github for follow the development and/or check for an updated version :)

## Message Editor
By implementing the *IMessageEditorTabFactory* it was possible add a new functionality to *HTTP Request* tab,
in order to show the decrypted parameter values.
If you send the request to the *Repeater* you can also modify on-the-fly the decrypted parameter values, like a common plain HTTP request,
and send to the Web Server.

## Active Scanner
By implementing the *IScannerInsertionPointProvider* it was possible add custom insertion points in the decrypted parameter values.
Let me explain by using the example from http://www.jcryption.org/#examples
<br>
Watch the following HTTP request:

```
POST /jcryption.php HTTP/1.1
Host: www.jcryption.org
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://www.jcryption.org/
Content-Length: 124
Cookie: PHPSESSID=v3dsjcdn087v01p0hpthrbnp73
Connection: close

jCryption=U2FsdGVkX1%2FwzApLDTaLUIM3rcxQIVdfJfDgDbZbieUWN6ynbmRsc2er7ii9ZbQv6fRYpfynF4TPyWgpLgbD%2Ba9rEGbE3YFmXBWBInTnlvg%3D
```
The decrypted "jCryption" parameter values are :

```
email=john%40smith.com&password=1234&role=Admin&remember=on
```

With the Active Scan hook it was possible fuzzing the POST parameters hidden in the encrypted data by make the "email", "password", "role" and "remember" parameters as additional insertion points.

## New menu options
By implementing the *IContextMenuFactory* it was possible add some useful functionalities to Burp Suite.
<br>
I added two main functions : "Send to Repeater" and "Send to Active Scan".
<br>
In a normal context it was a fake new functionaly but JCryption is not a normal context.
<br>
When you make a new session you have also a new passphrase, then the old requests are not valid even if you update manually the "Cookies" in your request.
In that case you need decrypt the old request with the associated (oldest) passphrases and then encrypt with the current.
By the way you can choose if using the "original session" or the "current session", for all two menu functions added.

(To be continued)
