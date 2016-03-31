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

use Jose\Object\JWK;
use Jose\Object\JWKSet;

trait PasswordClientTrait
{
    /**
     * @var string[]
     */
    protected $allowed_signature_algorithms = [];

    /**
     * @var string
     */
    protected $secret;

    /**
     * {@inheritdoc}
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignaturePublicKeySet()
    {
        $jwk_set = new JWKSet();
        $jwk_set = $jwk_set->addKey(new JWK([
            'kty' => 'oct',
            'k'   => $this->secret,
        ]));

        return $jwk_set;
    }

    /**
     * @param array $allowed_signature_algorithms
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
