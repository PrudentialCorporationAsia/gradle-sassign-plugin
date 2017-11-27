# Symantec Secure App Service (SAS) Gradle plugin

## License

This is provided under the [Apache 2.0 License](LICENSE.txt).

## Description

### Overview

This is a gradle plugin to invoke the Secure App Service (SAS) from Symantec. This is specically
targetted at signing Android APK files. The plugin will create a new signing set for each attempt,
with the version number, variant and date/time of the call. This is because the Symantec `version`
has to be unique.

### API Documentation

The Symantec API documentation can be found on the
[Symantec Developer's site](https://developers.websecurity.symantec.com/content/api/us/english/secureappserviceapi.html "Symantec Developer Site").

### Project layout

The main plugin is in the [plugin](plugin) directory. Various example of invoking the plugin can be
found inn the [examples](examples) directory.

## Configuration

### Plugin setup

When using the plugin, place the following properties into the `local.properties` file. This should not be checked
into source control, especially for public projects.

```ini
sas.publisherId=1234
sas.partnerCode=1234
sas.username=1234
sas.password=1234
sas.keystore=1234
sas.keystorePassword=1234
```

### Proxies

TODO

## Development environment setup

### Importing into IDEA

When importing the project, it is best to use the Gradle command line to generate the idea project first.

```sh
gradle idea
```

## Symantec endpoints

### Testing

* Web service: <https://test-api.ws.symantec.com/webtrust/SigningService>
* WSDL: <https://test-api.ws.symantec.com/webtrust/SigningService?wsdl>

### Production

* Web service: <https://api.ws.symantec.com/webtrust/SigningService>
* WSDL: <https://api.ws.symantec.com/webtrust/SigningService?wsdl>

## FIXME

* Lint - use Camel
* Copyright notices

