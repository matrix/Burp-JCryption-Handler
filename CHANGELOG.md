# Changelog

## v0.1 - 2017-07-02
Initial release

## v1.0 - 2017-07-03
- Add support for build project with gradle
- Add HTTP Responses handling
- Minor code changes
- Remove Burp-Extender-Api files (replaced with maven repository dependencies setting in build.grade)
- Add BApp Store HTML description

## v1.1 - 2017-07-04
- Replace printStackTrace() with RuntimeException()
- Fix UI (Preferences and About tabs)
- Add isBase64() function to check data before processing
- Add support for save/load extension settings
- Implement IExtensionStateListener interface, to save extension settings before unloading extension
- Update BApp Store HTML description

## v1.2 - 2017-07-06
- Update UI
- Refactor source code (move all UI code in BurpExtender.java, remove AboutPane and PreferencesPane files, remove almost alls static classes/methods/variables)
- Add IHttpRequestResponse implementation
- Add HTTP Response time calculation (in milliseconds) in Logger View
- Add import/export functionalities for Logger View data, using CSV format (comma-delimited)
- Update BApp Store HTML description

## v1.3 - 2017-07-10
- Update the encryption class to handle the jCryption library version 2.x (AES-CTR encrypted parameter)
- Update UI (add 'clear' button for cleanup persistent extension settings)
- Update UI (add drop-down combo box for select/show the current library version detected)
- Update UI (add another column to keep and reuse the library version for each request/response)
- Update the hijack javascript payload in order to make and XMLHttpRequest using the same protocol of web application (http or https)
- Update BApp Store HTML description

## v1.4 - 2017-07-15
- Update the encryption class to handle the RSA Public Key parsing, used in jCryption library version 1.x
- Fix 2 out of bounds exceptions
- Add Passive Scanner checks (Insecure Implementation of RSA Encryption in jCryption v1.x)
- Fix some typos
- Update FEATURES.md and README.md
- Update BApp Store HTML description

## v1.4.1 - 2017-07-16
- Update the encryption class to handle the encrypt using the RSA Public Key, used in jCryption library version 1.x
- Add full support for handling jCryption v1.x by exploit the Insecure RSA Implementation
- Update FEATURES.md
- Update BApp Store HTML description
