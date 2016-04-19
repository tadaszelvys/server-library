<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Client\Client as Base;
use OAuth2\Client\Extension\ScopePolicyExtensionInterface;
use OAuth2\Client\Extension\TokenLifetimeExtensionInterface;

class Client extends Base implements TokenLifetimeExtensionInterface, ScopePolicyExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getTokenLifetime($token)
    {
        if ($this->hasClientSecret()) {
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
        if ($this->hasPublicKeySet()) {
            switch ($token) {
                case 'authcode':
                    return 10;
                case 'access_token':
                    return 0;
                case 'refresh_token':
                default:
                    return 2000;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getScopePolicy()
    {
        if ($this->hasClientSecret()) {
            return 'none';
        }
        if ($this->hasPublicKeySet()) {
            return 'error';
        }
    }
}
