# Authorization Endpoint

The authorization endpoint is needed for every response types (e.g. Implicit or Authorization Code grants).
It displays a consent screen with a form. The resource owner (a user) has to accept or deny the authorization request.

Authorization requests and their parameters are loaded and verified by the Authorization Request Loader and the Authorization Factory.
Each parameter, if supported, is verified is checkers.

Authorization endpoint can load extensions to enhance it. Some extensions are provided by this library.

## The Authorization Request Loader

## The Authorization Factory

## The Authorization Endpoint

### Pre-Configured Authorizations Support
