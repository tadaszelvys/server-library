<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Client\AccessTokenTypeExtensionInterface;
use OAuth2\Client\PasswordClient as BasePasswordClient;
use OAuth2\Client\TokenLifetimeExtensionInterface;

class PasswordClient extends BasePasswordClient implements TokenLifetimeExtensionInterface, AccessTokenTypeExtensionInterface
{
    private $preferred_access_token_type = null;

    public function __construct($preferred_access_token_type = null)
    {
        parent::__construct();
        $this->preferred_access_token_type = $preferred_access_token_type;
    }

    /**
     * {@inheritdoc}
     */
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

    /**
     * {@inheritdoc}
     */
    public function getPreferredTokenType()
    {
        return $this->preferred_access_token_type;
    }
}
