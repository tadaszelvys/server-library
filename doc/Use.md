How to use
==========

This library provides all components to build an authorization server base on the OAuth2 Framework protocol.

Not all components are needed; it mainly depends on the features your authorization server has to provide.
However, you must at least the following ones:

* An exception manager
* A Scope manager
* A Client manager
* An User Account manager
* An Access Token manager
* At least one token type and the token type manager
* At least one grant type
* Depending on the grant types, at least one endpoint

# Exceptions and Exception Manager

The exception manager manages all exception types thrown during the authorization process.
It is used by almost all other components.

Please read [this page](component/exception.md) to know how to create and use this component.

# JWTLoader And JWTCreator

For components that need to create JWT or to load them, you will have to inject a `JWTLoader` or a `JWTCreator` object.

In general, you do not need to use them as they are directly used by components. You just have to indicate algorithms you want to support
and claims you want to check.

Please read [this page](component/jwt_loader_and_creator.md) to know how to create and use these components.

# Scope And Scope manager

Access tokens issued by this library may have a limited scope.
The scope is used by the resource servers 

Please read [this page](component/scope.md) to know how to create and use this component.

# Access Token Manager

The Access token Manager is one of the most important component in the OAuth2 Framework library.

This library is able to support any kind of access token managers.
You can create your own access token manager. It just has to implement `OAuth2\Token\AccessTokenManagerInterface`.

Or you can use the following implementations.

## Random String Access Token Manager

**This access token manager has been removed. Please use JWT Access Token Manager instead.**

## JWT Access Token Manager

This manager will produce access tokens based on JSON Web Token (JWT).
The tokens do not need a database and are digitally signed and encrypted by the authorization server.
Encryption is required in order to protect confidential information leak.

Please read [this page](component/jwt_access_token_manager.md) to know how to create and use this component.

# Token Types

When calling a protected resource, your client will have to demonstrate it is in possession of an access token.
To do so, each issued access token has a token type. The demonstration made by the client will vary depending on that type.

This library supports this token type and is able to support any kind of token type through a `Token Type Manager`.

This manager will handle token types enabled in your authorization server.

Please read [this page](component/token_type/manager.md) to know how to create and use this component.

# Users and Accounts

Please read [this page](component/user_manager.md) to know how to create and use this component.

# Clients and Client Manager

# Resource Servers

Resource servers are not yet fully supported.

# Endpoints

Please read [this page](component/endpoint/endpoints.md) to know how to create and use the endpoints provided by this library.

# Grant types

Please read [this page](component/grant/types.md) to know how to create and use the grant types provided by this library.

# OpenID Connect

To be written
