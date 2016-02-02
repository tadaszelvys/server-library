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

use Jose\Object\JWKSetInterface;

class JWTClient extends ConfidentialClient implements ClientWithSignatureCapabilitiesInterface
{
    /**
     * @var string[]
     */
    protected $allowed_signature_algorithms = [];

    /**
     * @var \Jose\Object\JWKSetInterface
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
    public function setSignaturePublicKeySet(JWKSetInterface $key_set)
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
