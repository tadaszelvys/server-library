OAuth2 Server Library
=====================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-library/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-library/?branch=master)
[![Coverage Status](https://coveralls.io/repos/Spomky-Labs/oauth2-server-library/badge.svg?branch=master&service=github)](https://coveralls.io/github/Spomky-Labs/oauth2-server-library?branch=master)
[![PHP 7 ready](http://php7ready.timesplinter.ch/Spomky-Labs/oauth2-server-library/badge.svg)](https://travis-ci.org/Spomky-Labs/oauth2-server-library)
[![PSR-7 ready](https://img.shields.io/badge/PSR--7-ready-brightgreen.svg)](http://www.php-fig.org/psr/psr-7/)


[![Build Status](https://travis-ci.org/Spomky-Labs/oauth2-server-library.svg?branch=master)](https://travis-ci.org/Spomky-Labs/oauth2-server-library)
[![HHVM Status](http://hhvm.h4cc.de/badge/spomky-labs/oauth2-server-library.svg)](http://hhvm.h4cc.de/package/spomky-labs/oauth2-server-library)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/3d678a80-f1b8-48a3-b36e-c7f0c6d45939/big.png)](https://insight.sensiolabs.com/projects/3d678a80-f1b8-48a3-b36e-c7f0c6d45939)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/v/stable.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/downloads.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)
[![License](https://poser.pugx.org/Spomky-Labs/oauth2-server-library/license.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-library)

*Note: if you use Symfony, [a bundle is available](https://github.com/Spomky-Labs/OAuth2ServerBundle).*

This library provides components to build an authorization server based on the OAuth2 Framework protocol ([RFC6749](https://tools.ietf.org/html/rfc6749)) and associated features.

The following components are implemented:

* [x] Access token manager:
    * [x] Simple string access token
    * [x] JWT access token
* [ ] Access token type:
    * [x] Bearer access token ([RFC6750](https://tools.ietf.org/html/rfc6750))
    * [ ] MAC access ([IETF draft](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05)) - *The implementation is stopped until the specification has not reach maturity*
* [x] Exception manager
* [ ] Clients:
    * [x] Public clients
    * [x] Password clients
        * [x] HTTP Basic Authentication Scheme
        * [x] HTTP Digest Authentication Scheme
        * [x] Credentials from request body
    * [ ] SAML clients ([RFC7522](https://tools.ietf.org/html/rfc7522))
    * [x] JWT clients ([RFC7523](https://tools.ietf.org/html/rfc7523))
    * [x] Unregistered clients
* [x] Endpoints:
    * [x] Authorization endpoint
    * [x] Token endpoint
    * [x] Token revocation endpoint ([RFC7009](https://tools.ietf.org/html/rfc7009))
* [ ] Grant types:
    * [x] Implicit grant type
    * [x] Authorization code grant type
    * [x] Client credentials grant type
    * [x] Resource Owner Password Credentials grant type
    * [x] Refresh token grant type
    * [ ] SAML grant type ([RFC7522](https://tools.ietf.org/html/rfc7522))
    * [x] JWT Bearer token grant type ([RFC7523](https://tools.ietf.org/html/rfc7523))

* [ ] OpenID Connect
    * [ ] [Core](http://openid.net/specs/openid-connect-core-1_0.html)
    * [ ] [Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
    * [ ] [Dynamic Registration](http://openid.net/specs/openid-connect-registration-1_0.html)
    * [x] [Multiple response types](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
    * [x] [Form post response mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
    * [ ] [Session Management](http://openid.net/specs/openid-connect-session-1_0.html)
    * [ ] [HTTP Based logout](http://openid.net/specs/openid-connect-logout-1_0.html)

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least ![PHP 5.6+](https://img.shields.io/badge/PHP-5.6%2B-ff69b4.svg).

It has been successfully tested using `PHP 5.6`, `PHP 7` and `HHVM`.

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require "spomky-labs/oauth2-server-library" "dev-master"
```

# Create missing components

Look at [Extend classes](doc/Extend.md) for more information and examples.

# How to use

Have a look at [How to use](doc/Use.md) to use OAuth2 server and handle your first requests.

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome. [Please follow these best practices](doc/Contributing.md).

# Licence

This library is release under [MIT licence](LICENSE.txt).
