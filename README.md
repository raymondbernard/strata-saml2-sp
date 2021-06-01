# SAML-test-SP is a non-docker Saml testing plaform. 



The mission of this repo is to create a small, golang-based SAML Service Provider or  SP.   This tool hopes to addresses End-to-end use cases or other testing scenarios.

Note: This is initially a fork from https://github.com/BeryJu/saml-test-sp
The repo depends on the code from https://github.com/crewjam/saml 


## Refactoring goals.
Our version is refactored the same behavior into clear golang code.
One of its best attributes of Golang is how readable and powerful it is.   As a result, the effort behind this repo is to make things easier to evaluate, extend and support the long-term feature set of this application.  

Note the original version of this fork lacks underlying unit tests.  As a result, we will be writing them as we begin to evaluate the underlying code.   Our primary focus is to harden this repo by completing this effort.

Beware, according to the original repo, this tool supports IdP-initiated login workflows;* however* RelayState has to be empty for this to work!!  

As a result, work needs could be done to add greater flexibility. This should be an active area of the investigation when the need arises. 
Currently, the original version and this repo have feature symmetry.  We anticipate we will maintain backward compatibility but will be free to add new features as the marketplace demand. 




This tool is full configured using environment variables.

## URLs

- `http://localhost:9009/health`: Healthcheck URL, used by the docker healtcheck.
- `http://localhost:9009/saml/acs`: SAML ACS URL, needed to configure your IdP.
- `http://localhost:9009/saml/metadata`: SAML Metadata URL, needed to configure your IdP.
- `http://localhost:9009/`: Test URL, redirects to SAML SSO URL.
 

 
## Configuration

- `SP_BIND`: Which address and port to bind to. Defaults to `0.0.0.0:9009`.
- `SP_ROOT_URL`: Root URL you're using to access the SP. Defaults to `http://localhost:9009`.
- `SP_ENTITY_ID`: SAML EntityID, defaults to `saml-test-sp`
- `SP_METADATA_URL`: Optional URL that metadata is fetched from. The metadata is fetched on the first request to `/`
---
- `SP_SSO_URL`: If the metadata URL is not configured, use these options to configure it manually.
- `SP_SSO_BINDING`: Binding Type used for the IdP, defaults to POST. Allowed values: `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST` and `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`
- `SP_SIGNING_CERT`: PEM-encoded Certificate used for signing, with the PEM Header and all newlines removed.
---
Optionally, if you want to use SSL, set these variables
- `SP_SSL_CERT`: Path to the SSL Certificate the server should use.
- `SP_SSL_KEY`: Path to the SSL Key the server should use.

Note: If you're manually setting `SP_ROOT_URL`, ensure that you prefix that URL with https.

## Running
go run main.go


