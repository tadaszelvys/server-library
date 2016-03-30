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

use OAuth2\Client\Extension\ScopePolicyExtensionInterface;
use OAuth2\Client\PasswordClient as BasePasswordClient;
use OAuth2\Client\Extension\TokenLifetimeExtensionInterface;

class PasswordClient extends BasePasswordClient implements TokenLifetimeExtensionInterface, ScopePolicyExtensionInterface
{
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
     * @param string $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * @param string[] $redirect_uris
     */
    public function setRedirectUris(array $redirect_uris)
    {
        $this->redirect_uris = $redirect_uris;
    }

    /**
     * @param string $redirect_uri
     */
    public function addRedirectUri($redirect_uri)
    {
        if (!$this->hasRedirectUri($redirect_uri)) {
            $this->redirect_uris[] = $redirect_uri;
        }
    }

    /**
     * @param string $redirect_uri
     */
    public function removeRedirectUri($redirect_uri)
    {
        $key = array_search($redirect_uri, $this->redirect_uris);
        if (false !== $key) {
            unset($this->redirect_uris[$key]);
        }
    }

    /**
     * @param string $grant_type
     */
    public function addAllowedGrantType($grant_type)
    {
        if (!$this->isGrantTypeAllowed($grant_type)) {
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
        if (!$this->isResponseTypeAllowed($response_type)) {
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

    /**
     * @param string[] $token_types
     */
    public function setAllowedTokenTypes(array $token_types)
    {
        $this->token_types = $token_types;
    }

    public function getScopePolicy()
    {
        return 'none';
    }
}
