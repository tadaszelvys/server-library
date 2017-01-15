# How to use

This library provides all components to build an authorization server base on the OAuth2 Framework protocol.

Not all components are needed; it mainly depends on the features your authorization server has to provide.

## Access Token Manager

The Access token Manager is one of the most important component in the OAuth2 Framework library.

This library is able to support any kind of access token managers.
You can create your own access token manager. It just has to implement `OAuth2\Token\AccessTokenManagerInterface`.

Or you can use the following implementations:

* Random String Access Token Manager: Access token based on a random string - *To be written*
* JWT Access Token Manager: [Access tokens based on JSON Web Token (JWT).](component/jwt_access_token_manager.md) to know how to create and use this component.

## Token Types

When calling a protected resource, your client will have to demonstrate it is in possession of an access token.
To do so, each issued access token has a token type. The demonstration made by the client will vary depending on that type.

This library is able to support any kind of token type through a `Token Type Manager`.

Please read [this page](component/token_type/manager.md) to know how to create and use this component.

## Users and Accounts

Please read [this page](component/user_account/manager.md) to know how to create and use this component.

## Clients and Client Manager

Please read [this page](component/client/manager.md) to know how to create and use this component.

## Resource Servers

Resource servers are not yet fully supported.

## Endpoints

Please read [this page](component/endpoint/endpoints.md) to know how to create and use the endpoints provided by this library.

## Grant types

Please read [this page](component/grant/types.md) to know how to create and use the grant types provided by this library.

## Response Modes

Please read [this page](component/response_mode/manager.md) to know how to create and use the response modes provided by this library.

## JWTLoader And JWTCreator

For components that need to create JWT or to load them, you will have to inject a `JWTLoader` or a `JWTCreator` object.

In general, you do not need to use them as they are directly used by components. You just have to indicate algorithms you want to support
and claims you want to check.

Please read [this page](component/jwt_loader_and_creator.md) to know how to create and use these components.

## Scope And Scope manager

Tokens issued by this library may have a limited scope.
The scope is used by the resource servers for example for operation limitations.

Please read [this page](component/scope.md) to know how to create and use this component.


## OpenID Connect

*To be written*
