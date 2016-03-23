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

use Jose\Object\JWKSetInterface;
use OAuth2\Client\JWTClient as BaseJWTClient;
use OAuth2\Client\TokenLifetimeExtensionInterface;

class JWTClient extends BaseJWTClient implements TokenLifetimeExtensionInterface
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
     * @param \Jose\Object\JWKSetInterface $key_set
     */
    public function setSignaturePublicKeySet(JWKSetInterface $key_set)
    {
        $this->signature_public_key_set = $key_set;
    }

    /**
     * @param array $allowed_signature_algorithms
     */
    public function setAllowedSignatureAlgorithms(array $allowed_signature_algorithms)
    {
        $this->allowed_signature_algorithms = $allowed_signature_algorithms;
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
}
