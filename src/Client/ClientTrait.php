<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use Assert\Assertion;
use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Object\JWKSet;

/**
 * Class ClientTrait.
 *
 * @method string getJwksUri()
 * @method bool hasJwksUri()
 * @method array getJwks()
 * @method bool hasJwks()
 * @method string getClientSecret()
 * @method bool hasClientSecret()
 */
trait ClientTrait
{
    /**
     * @param string $metadata
     *
     * @return bool
     */
    abstract public function has($metadata);

    /**
     * @param string $metadata
     *
     * @return mixed
     */
    abstract public function get($metadata);

    /**
     * {@inheritdoc}
     */
    public function isGrantTypeAllowed($grant_type)
    {
        Assertion::string($grant_type, 'Argument must be a string.');
        $grant_types = $this->get('grant_types');
        Assertion::isArray($grant_types, 'The metadata "grant_types" must be an array.');

        return in_array($grant_type, $grant_types);
    }

    /**
     * {@inheritdoc}
     */
    public function isResponseTypeAllowed($response_type)
    {
        Assertion::string($response_type, 'Argument must be a string.');
        $response_types = $this->get('response_types');
        Assertion::isArray($response_types, 'The metadata "response_types" must be an array.');

        return in_array($response_type, $response_types);
    }

    /**
     * {@inheritdoc}
     */
    public function isTokenTypeAllowed($token_type)
    {
        Assertion::string($token_type, 'Argument must be a string.');
        if (!$this->has('token_types')) {
            return true;
        }
        $token_types = $this->get('token_types');
        Assertion::isArray($token_types, 'The metadata "token_types" must be an array.');

        return in_array($token_type, $token_types);
    }

    /**
     * {@inheritdoc}
     */
    public function isPublic()
    {
        return 'none' === $this->getTokenEndpointAuthMethod();
    }

    /**
     * @return string
     */
    public function getTokenEndpointAuthMethod()
    {
        if ($this->has('token_endpoint_auth_method')) {
            return $this->get('token_endpoint_auth_method');
        }

        return 'client_secret_basic';
    }

    /**
     * @return int
     */
    public function getClientSecretExpiresAt()
    {
        if ($this->has('client_secret_expires_at')) {
            return $this->get('client_secret_expires_at');
        }
        
        return 0;
    }

    /**
     * {@inheritdoc}
     */
    public function areClientCredentialsExpired()
    {
        if (0 === $this->getClientSecretExpiresAt()) {
            return false;
        }

        return time() > $this->getClientSecretExpiresAt();
    }

    /**
     * @return bool
     */
    public function hasPublicKeySet()
    {
        return $this->hasJwks() || $this->hasJwksUri() || $this->hasClientSecret();
    }

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    public function getPublicKeySet()
    {
        Assertion::true($this->hasPublicKeySet(), 'The client has no public key set');

        if ($this->hasJwks()) {
            return new JWKSet($this->getJwks());
        }
        if ($this->hasJwksUri()) {
            return JWKFactory::createFromJKU($this->getJwksUri());
        }

        $jwk_set = new JWKSet();
        $jwk_set->addKey(new JWK([
            'kty' => 'oct',
            'use' => 'sig',
            'k'   => $this->getClientSecret(),
        ]));

        return $jwk_set;
    }
}
