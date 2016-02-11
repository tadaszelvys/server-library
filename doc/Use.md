How to use
==========

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

## Token Type Manager

##  Bearer Token Type

##  MAC Token Type

##  POP Token Type

This token type is not supported at the moment.

# End User Manager

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


