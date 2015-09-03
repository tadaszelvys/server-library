<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Client\UnregisteredClient as BaseUnregisteredClient;

class UnregisteredClient extends BaseUnregisteredClient implements TokenLifetimeExtensionInterface
{
    public function getTokenLifetime($token)
    {
        switch ($token) {
            case 'authcode':
                return 10;
            case 'access_token':
                return 1000;
            case 'refresh_token':
            default:
                return 2000;
        }
    }
}
