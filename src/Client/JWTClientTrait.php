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
use Jose\Object\JWKInterface;

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
     * @var string|null
     */
    protected $key_encryption_algorithm = null;

    /**
     * @var string|null
     */
    protected $content_encryption_algorithm = null;

    /**
     * @var \Jose\Object\JWKInterface
     */
    protected $encryption_public_key = null;

    /**
     * {@inheritdoc}
     */
    public function isEncryptionSupportEnabled()
    {
        return null !== $this->encryption_public_key;
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
    public function getAllowedSignatureAlgorithms()
    {
        return $this->allowed_signature_algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptionPublicKey()
    {
        return $this->encryption_public_key;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyEncryptionAlgorithm()
    {
        return $this->key_encryption_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getContentEncryptionAlgorithm()
    {
        return $this->content_encryption_algorithm;
    }

    /**
     * @param \Jose\Object\JWKInterface $encryption_public_key
     */
    public function setEncryptionPublicKey(JWKInterface $encryption_public_key)
    {
        $this->encryption_public_key = $encryption_public_key;
    }

    /**
     * @param string $content_encryption_algorithm
     */
    public function setContentEncryptionAlgorithm($content_encryption_algorithm)
    {
        Assertion::string($content_encryption_algorithm);
        $this->content_encryption_algorithm = $content_encryption_algorithm;
    }

    /**
     * @param string $key_encryption_algorithm
     */
    public function setKeyEncryptionAlgorithm($key_encryption_algorithm)
    {
        Assertion::string($key_encryption_algorithm);
        $this->key_encryption_algorithm = $key_encryption_algorithm;
    }
}
