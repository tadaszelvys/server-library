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

use Jose\Factory\EncrypterFactory;
use Jose\Factory\JWEFactory;
use Jose\Factory\JWSFactory;
use Jose\Factory\SignerFactory;
use Jose\Object\JWKInterface;

final class JWTCreator
{
    /**
     * @var \Jose\EncrypterInterface
     */
    private $encrypter;

    /**
     * @var \Jose\SignerInterface
     */
    private $signer;

    /**
     * @var string[]
     */
    private $signature_algorithms;

    /**
     * @var string[]
     */
    private $key_encryption_algorithms;

    /**
     * @var string[]
     */
    private $content_encryption_algorithms;

    /**
     * JWTCreator constructor.
     *
     * @param string[]                       $signature_algorithms
     * @param string[]                       $key_encryption_algorithms
     * @param string[]                       $content_encryption_algorithms
     */
    public function __construct(array $signature_algorithms,
                                array $key_encryption_algorithms = [],
                                array $content_encryption_algorithms = []
    ) {
        $this->signature_algorithms = $signature_algorithms;
        $this->key_encryption_algorithms = $key_encryption_algorithms;
        $this->content_encryption_algorithms = $content_encryption_algorithms;

        $this->signer = SignerFactory::createSigner($signature_algorithms);
        $this->encrypter = EncrypterFactory::createEncrypter(array_merge($key_encryption_algorithms, $content_encryption_algorithms));
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
        $jws = JWSFactory::createJWS($payload);

        $this->signer->addSignature(
            $jws,
            $signature_key,
            $signature_protected_headers
        );

        return $jws->toCompactJSON(0);
    }

    /**
     * @param string                         $payload
     * @param array                          $encryption_protected_headers
     * @param \Jose\Object\JWKInterface      $encryption_key
     * @param \Jose\Object\JWKInterface|null $sender_key
     *
     * @return string
     */
    public function encrypt($payload, array $encryption_protected_headers, JWKInterface $encryption_key, JWKInterface $sender_key = null)
    {
        $jwe = JWEFactory::createJWE($payload, $encryption_protected_headers);

        $this->encrypter->addRecipient(
            $jwe,
            $encryption_key,
            $sender_key
        );

        return $jwe->toCompactJSON(0);
    }

    /**
     * @return string[]
     */
    public function getSignatureAlgorithms()
    {
        return $this->signature_algorithms;
    }

    /**
     * @return string[]
     */
    public function getKeyEncryptionAlgorithms()
    {
        return $this->key_encryption_algorithms;
    }

    /**
     * @return string[]
     */
    public function getContentEncryptionAlgorithms()
    {
        return $this->content_encryption_algorithms;
    }
}
