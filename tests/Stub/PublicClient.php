<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Client\PublicClient as BasePublicClient;

class PublicClient extends BasePublicClient implements TokenLifetimeExtensionInterface
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
