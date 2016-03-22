<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Util;

use Assert\Assertion;
use Jose\Factory\JWEFactory;
use Jose\Factory\JWSFactory;
use Jose\Object\JWKInterface;

final class JWTCreator
{
    /**
     * @var string[]
     */
    private $supported_signature_algorithms;

    /**
     * @var string[]
     */
    private $supported_key_encryption_algorithms;

    /**
     * @var string[]
     */
    private $supported_content_encryption_algorithms;

    /**
     * JWTCreator constructor.
     *
     * @param string[] $supported_signature_algorithms
     */
    public function __construct(array $supported_signature_algorithms)
    {
        Assertion::notEmpty($supported_signature_algorithms);
        
        $this->supported_signature_algorithms = $supported_signature_algorithms;
    }

    /**
     * @param string[] $supported_key_encryption_algorithms
     * @param string[] $supported_content_encryption_algorithms
     */
    public function enableEncryptionSupport(array $supported_key_encryption_algorithms,
                                            array $supported_content_encryption_algorithms
    ){
        Assertion::notEmpty($supported_key_encryption_algorithms, 'At least one key encryption algorithm must be set.');
        Assertion::notEmpty($supported_content_encryption_algorithms, 'At least one content encryption algorithm must be set.');

        $this->supported_key_encryption_algorithms = $supported_key_encryption_algorithms;
        $this->supported_content_encryption_algorithms = $supported_content_encryption_algorithms;
    }

    /**
     * @param mixed                     $payload
     * @param array                     $signature_protected_headers
     * @param \Jose\Object\JWKInterface $signature_key
     *
     * @return string
     */
    public function sign($payload, array $signature_protected_headers, JWKInterface $signature_key)
    {
        return JWSFactory::createJWSToCompactJSON($payload, $signature_key, $signature_protected_headers);
    }

    /**
     * @param string                    $payload
     * @param array                     $encryption_protected_headers
     * @param \Jose\Object\JWKInterface $encryption_key
     *
     * @return string
     */
    public function encrypt($payload, array $encryption_protected_headers, JWKInterface $encryption_key)
    {
        return JWEFactory::createJWEToCompactJSON($payload, $encryption_key, $encryption_protected_headers);
    }

    /**
     * @return string[]
     */
    public function getSignatureAlgorithms()
    {
        return $this->supported_signature_algorithms;
    }

    /**
     * @return string[]
     */
    public function getKeyEncryptionAlgorithms()
    {
        return $this->supported_key_encryption_algorithms;
    }

    /**
     * @return string[]
     */
    public function getContentEncryptionAlgorithms()
    {
        return $this->supported_content_encryption_algorithms;
    }
}
