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

trait JWTClientTrait
{
    /**
     * @var string[]
     */
    protected $allowed_signature_algorithms = [];

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    protected $signature_public_key_set;

    /**
     * @var string[]
     */
    protected $supported_encryption_algorithms = [];

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    protected $encryption_public_key_set;

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
    public function getAllowedSignatureAlgorithms()
    {
        return $this->allowed_signature_algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptionPublicKeySet()
    {
        return $this->encryption_public_key_set;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedEncryptionAlgorithms()
    {
        return $this->supported_encryption_algorithms;
    }
}
