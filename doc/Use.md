How to use
==========

This library provides all components to build an authorization server base on the OAuth2 Framework protocol.
The following components must be created, configured to create a fully featured authorization server.

# Exceptions and Exception Manager

The exception manager manages all exception types thrown during the authorization process.
It is used by almost all other components.

Please read [this page](component/exception.md) to know how to create and use this component.

# Scope And Scope manager

Access tokens issued by this library may have a limited scope.
The scope is used by the resource servers 

Please read [this page](component/scope.md) to know how to create and use this component.

# Access Token Manager

Access tokens are one of the most important components in the OAuth2.
They are issued by the authorization server to the clients.

This library is able to support any kind of access token managers.
You can create your own access token manager. It just has to implement `OAuth2\Token\AccessTokenManagerInterface`.

Or you can use the following implementation.

## JWT Access Token Manager

This manager will produce access tokens JSON Web Token (JWT) based.
The tokens do not need a database and are digitaly signed by the authorization server.
They can also be encrypted in order to protect confidential information leak.

Please read [this page](component/jwt_access_token_manager.md) to know how to create and use this component.

# Token Types

When calling a protected resource, your client will have to demonstrate it is in possesion of an access token.
To do so, each issued access token has a token type. The demonstration made by the client will vary depending on that type.

This library supports this token type and is able to support any kind of token type through a `Token Type Manager`.

## Token Type Manager

This manager will handle token types enabled in your authorization server.

You must add at least one token type.

Please read [this page](component/token_type_manager.md) to know how to create and use this component.

##  Bearer Token Type

The `Bearer Token Type` (see [RFC6750](https://tools.ietf.org/html/rfc6750)) is most common token type.

Please read [this page](component/bearer_token_type.md) to know how to create and use this component.

##  MAC Token Type

The `MAC Token Type` is an authentication scheme that uses a message authentication code (MAC) algorithm to provide cryptographic verification of the HTTP requests.

Please note that this specification is not yet stable. This library provides a MAC Token Type support, but it is limited to the [revision 2 of the specification](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02). No update will be made until this specifition has not reach maturity.

Please read [this page](component/mac_token_type.md) to know how to create and use this component.

##  POP Token Type

This token type is not supported at the moment.

For more information, please follow the links hereafter:

* https://tools.ietf.org/html/draft-ietf-oauth-pop-architecture
* https://tools.ietf.org/html/draft-ietf-oauth-pop-key-distribution-02
* https://tools.ietf.org/html/draft-ietf-oauth-proof-of-possession-11

# User Manager

Please read [this page](component/user_manager.md) to know how to create and use this component.

# Client Manager Supervisor and Client Managers

## Client Manager Supervisor

## Public Client Manager

## Password Client Manager

## JWT Client Manager

## Unregistered Client Manager

# Resource Servers

# Endpoints

## Authorization Endpoint

## Token Endpoint

## Token Revocation Endpoint

## Token Introspection Endpoint

# Grant types

## Authorization Code Grant Type

### Proof Key for Code Exchange by OAuth Public Clients

#### Plain

#### S256

## Implicit Code Grant Type

## Resource Owner Password Credentials Code Grant Type

## Client Credentials Code Grant Type

## Refresh Token Code Grant Type

## JWT Bearer Token Code Grant Type

# OpenID Connect


