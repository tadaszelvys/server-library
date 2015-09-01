OAuth2 Server Library
==================================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-library/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-library/?branch=master)
[![Coverage Status](https://coveralls.io/repos/Spomky-Labs/oauth2-server-library/badge.svg?branch=master&service=github)](https://coveralls.io/github/Spomky-Labs/oauth2-server-library?branch=master)
[![PHP 7 ready](http://php7ready.timesplinter.ch/Spomky-Labs/oauth2-server-library/badge.svg)](https://travis-ci.org/Spomky-Labs/oauth2-server-library)

[![Build Status](https://travis-ci.org/Spomky-Labs/oauth2-server-library.svg?branch=master)](https://travis-ci.org/Spomky-Labs/oauth2-server-library)
[![HHVM Status](http://hhvm.h4cc.de/badge/spomky-labs/oauth2-server-library.svg)](http://hhvm.h4cc.de/package/spomky-labs/oauth2-server-library)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/3d678a80-f1b8-48a3-b36e-c7f0c6d45939/big.png)](https://insight.sensiolabs.com/projects/3d678a80-f1b8-48a3-b36e-c7f0c6d45939)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/v/stable.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/downloads.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)
[![License](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/license.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)

*Note: if you use Symfony, [a bundle is available](https://github.com/Spomky-Labs/OAuth2ServerBundle).*

This library provides components to build an authorization server based on the OAuth2 Framework protocol ([RFC6749](https://tools.ietf.org/html/rfc6749)) and associated behaviours.

The following components:

* Access token manager:
    * [x] Simple string access token
    * [x] JWT access token (WIP)
* Access token transport:
    * [x] Bearer access token ([RFC6750](https://tools.ietf.org/html/rfc6750))
    * [ ] MAC access ([IETF draft](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05))
* [x] Exception manager
* Clients:
    * [x] Public clients
    * [x] Password clients
    * [x] JWT clients ([RFC7523](https://tools.ietf.org/html/rfc7523))
    * [x] Unregistered clients
* Endpoints:
    * [x] Authorization endpoint
    * [x] Token endpoint
    * [x] Token revocation endpoint ([RFC7009](https://tools.ietf.org/html/rfc7009))
* Grant types:
    * [x] Implicit grant type
    * [x] Authorization code grant type
    * [x] Client credentials grant type
    * [x] Resource Owner Password Credentials grant type
    * [x] Refresh token grant type
    * [ ] JWT Bearer token grant type (WIP - [RFC7523](https://tools.ietf.org/html/rfc7523))

* [ ] OpenID Connect
    * [ ] Core
    * [ ] Discovery
    * [ ] Dynamic Registration
    * [ ] Multiple response types
    * [ ] Form post response mode
    * [ ] Session Management
    * [ ] HTTP Based logout

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least ![PHP 5.5+](https://img.shields.io/badge/PHP-5.5%2B-ff69b4.svg).

It has been successfully tested using `PHP 5.5`, `PHP 5.6`, `PHP 7` and `HHVM`

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require "spomky-labs/oauth2-server-library" "~1.0"
```

# Create missing components

Look at [Extend classes](doc/Extend.md) for more information and examples.

# How to use

Have a look at [How to use](doc/Use.md) to use OAuth2 server and handle your first requests.

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome. [Please follow these best practices](doc/Contributing.md).

# Licence

This library is release under [MIT licence](LICENSE.txt).
