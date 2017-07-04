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
