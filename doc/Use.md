How to use
==========

This library provides all components to build an authorization server base on the OAuth2 Framework protocol.
The following components must be created, configured to create a fully featured authorization server.

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

Or you can use the following implementation.

## Random String Access Token Manager

**This access token manager has been removed. Please use JWT Access Token Manager instead.**

## JWT Access Token Manager

This manager will produce access tokens based on JSON Web Token (JWT).
The tokens do not need a database and are digitally signed by the authorization server.
They can also be encrypted in order to protect confidential information leak.
The encryption is performed using the encryption key of the resource server or, if not available, of the authorization server.

Please read [this page](component/jwt_access_token_manager.md) to know how to create and use this component.

# Token Types

When calling a protected resource, your client will have to demonstrate it is in possession of an access token.
To do so, each issued access token has a token type. The demonstration made by the client will vary depending on that type.

This library supports this token type and is able to support any kind of token type through a `Token Type Manager`.

This manager will handle token types enabled in your authorization server.

Please read [this page](component/token_type/manager.md) to know how to create and use this component.

# Users

Please read [this page](component/user_manager.md) to know how to create and use this component.

# Client Manager Supervisor and Client Managers

## Client Manager Supervisor

The role of the client manager supervisor is to manager all client managers you need.
It will handle requests and try to identify which client is sending requests against the authorization server.

Please read [this page](component/client/manager_supervisor.md) to know how to create and use this component.

# Resource Servers

Resource servers are not yet fully supported.

# Endpoints

Please read [this page](component/endpoint/endpoints.md) to know how to create and use the endpoints provided by this library.

# Grant types

Please read [this page](component/grant/types.md) to know how to create and use the grant types provided by this library.
