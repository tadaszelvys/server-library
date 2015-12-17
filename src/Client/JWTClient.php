<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

class JWTClient extends ConfidentialClient implements JWTClientInterface
{
    /**
     * @var string[]
     */
    protected $allowed_signature_algorithms = [];

    /**
     * @var array
     */
    protected $signature_public_key_set = [];

    public function __construct()
    {
        parent::__construct();
        $this->setType('jwt_client');
    }

    /**
     * {@inheritdoc}
     */
    public function setSignaturePublicKeySet(array $key_set)
    {
        $this->signature_public_key_set = $key_set;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignaturePublicKeySet()
    {
        return $this->signature_public_key_set;
    }

    /**
     * {@inheritdoc}
     */
    public function setAllowedSignatureAlgorithms(array $allowed_signature_algorithms)
    {
        $this->allowed_signature_algorithms = $allowed_signature_algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedSignatureAlgorithms()
    {
        return $this->allowed_signature_algorithms;
    }
}
