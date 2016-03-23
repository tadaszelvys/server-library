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

    /**
     * @param string $grant_type
     */
    public function addAllowedGrantType($grant_type)
    {
        if (!$this->isAllowedGrantType($grant_type)) {
            $this->grant_types[] = $grant_type;
        }
    }

    /**
     * @param string[] $grant_types
     */
    public function setAllowedGrantTypes(array $grant_types)
    {
        $this->grant_types = $grant_types;
    }

    /**
     * @param string $grant_type
     */
    public function removeAllowedGrantType($grant_type)
    {
        $key = array_search($grant_type, $this->grant_types);
        if (false !== $key) {
            unset($this->grant_types[$key]);
        }
    }

    /**
     * @param string $response_type
     */
    public function addAllowedResponseType($response_type)
    {
        if (!$this->isAllowedResponseType($response_type)) {
            $this->response_types[] = $response_type;
        }
    }

    /**
     * @param string[] $response_types
     */
    public function setAllowedResponseTypes(array $response_types)
    {
        $this->response_types = $response_types;
    }

    /**
     * @param string $response_type
     */
    public function removeAllowedResponseType($response_type)
    {
        $key = array_search($response_type, $this->response_types);
        if (false !== $key) {
            unset($this->response_types[$key]);
        }
    }
}
