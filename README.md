OAuth2 Server Utils
===================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-utils/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-utils/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-utils/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-utils/?branch=master)

[![Build Status](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-utils/badges/build.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/oauth2-server-utils/build-status/master)
[![HHVM Status](http://hhvm.h4cc.de/badge/spomky-labs/oauth2-server-utils.svg)](http://hhvm.h4cc.de/package/spomky-labs/oauth2-server-utils)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/5821de19-efbe-4838-a1e5-b7d45aa6f195/big.png)](https://insight.sensiolabs.com/projects/5821de19-efbe-4838-a1e5-b7d45aa6f195)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/oauth2-server-utils/v/stable.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-utils)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/oauth2-server-utils/downloads.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-utils)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/oauth2-server-utils/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-utils)
[![License](https://poser.pugx.org/Spomky-Labs/oauth2-server-utils/license.png)](https://packagist.org/packages/Spomky-Labs/oauth2-server-utils)

This library provides some utilities to get parameters from requests and to help building URIs.
It is part of the OAuth2 Project, but could be used alone.

## The Release Process ##

We manage its releases through features and time-based models.

- A new patch version comes out every month when you made backwards-compatible bug fixes.
- A new minor version comes every six months when we added functionality in a backwards-compatible manner.
- A new major version comes every year when we make incompatible API changes.

The meaning of "patch" "minor" and "major" comes from the Semantic [Versioning strategy](http://semver.org/).

This release process applies from version 3.0.x.

### Backwards Compatibility

We allow developers to upgrade with confidence from one minor version to the next one.

Whenever keeping backward compatibility is not possible, the feature, the enhancement or the bug fix will be scheduled for the next major version.

## Prerequisites ##

This library needs at least `PHP 5.4`.
It has been successfully tested using `PHP 5.4` to `PHP 5.6` and `HHVM`

## Installation ##

The preferred way to install this library is to rely on Composer:

```sh
    composer require "spomky-labs/oauth2-server-utils" "~4.0"
```

## How to use ##

Your classes are ready to use? Have a look at [How to use](doc/Use.md) to use your exception manager with an OAuth2 server.

## Contributing ##

Requests for new features, bug fixed and all other ideas to make this library usefull are welcome. [Please follow these best practices](doc/Contributing.md).

## Licence ##

This library is release under [MIT licence](LICENSE.txt).
