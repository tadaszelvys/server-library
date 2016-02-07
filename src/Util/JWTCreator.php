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
     * @var string
     */
    private $signature_algorithm;

    /**
     * @var \Jose\Object\JWKInterface
     */
    private $signature_key;

    /**
     * @var string|null
     */
    private $key_encryption_algorithm;

    /**
     * @var string|null
     */
    private $content_encryption_algorithm;

    /**
     * @var \Jose\Object\JWKInterface
     */
    private $sender_key = null;

    /**
     * JWTCreator constructor.
     *
     * @param string                         $signature_algorithm
     * @param \Jose\Object\JWKInterface      $signature_key
     * @param string|null                    $key_encryption_algorithm
     * @param string|null                    $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface|null $sender_key
     */
    public function __construct($signature_algorithm, JWKInterface $signature_key, $key_encryption_algorithm = null, $content_encryption_algorithm = null, JWKInterface $sender_key = null)
    {
        Assertion::string($signature_algorithm);
        Assertion::nullOrString($key_encryption_algorithm);
        Assertion::nullOrString($content_encryption_algorithm);
        $this->signature_key = $signature_key;
        $this->signature_algorithm = $signature_algorithm;
        $this->key_encryption_algorithm = $key_encryption_algorithm;
        $this->content_encryption_algorithm = $content_encryption_algorithm;

        $this->signer = SignerFactory::createSigner([$signature_algorithm]);

        if (null !== $key_encryption_algorithm && null !== $content_encryption_algorithm) {
            $this->encrypter = EncrypterFactory::createEncrypter([$key_encryption_algorithm, $content_encryption_algorithm]);
            $this->sender_key = $sender_key;
        }
    }

    /**
     * @param array                     $claims
     * @param array                     $signature_protected_headers
     * @param bool                      $encryption_required
     * @param array                     $encryption_protected_headers
     * @param \Jose\Object\JWKInterface $encryption_key
     *
     * @return string
     */
    public function createJWT(array $claims, array $signature_protected_headers, $encryption_required, array $encryption_protected_headers = [], JWKInterface $encryption_key = null)
    {
        Assertion::boolean($encryption_required);

        $data = $this->createJWS($claims, $signature_protected_headers);

        if (null !== $this->encrypter && null !== $encryption_key) {
            $data = $this->createJWE($data, $encryption_protected_headers, $encryption_key);
        }

        return $data;
    }

    /**
     * @return \Jose\Object\JWKInterface|null
     */
    public function getSenderKey()
    {
        return $this->sender_key;
    }

    /**
     * @return string
     */
    public function getSignatureAlgorithm()
    {
        return $this->signature_algorithm;
    }

    /**
     * @return string|null
     */
    public function getKeyEncryptionAlgorithm()
    {
        return $this->key_encryption_algorithm;
    }

    /**
     * @return string|null
     */
    public function getContentEncryptionAlgorithm()
    {
        return $this->content_encryption_algorithm;
    }

    /**
     * @param array $claims
     * @param array $signature_protected_headers
     *
     * @return string
     */
    private function createJWS(array $claims, array $signature_protected_headers)
    {
        $jws = JWSFactory::createJWS($claims);

        $this->signer->addSignature(
            $jws,
            $this->signature_key,
            $signature_protected_headers
        );

        return $jws->toCompactJSON(0);
    }

    /**
     * @param string                    $payload
     * @param array                     $encryption_protected_headers
     * @param \Jose\Object\JWKInterface $encryption_key
     *
     * @return string
     */
    private function createJWE($payload, array $encryption_protected_headers, JWKInterface $encryption_key)
    {
        $jwe = JWEFactory::createJWE($payload, $encryption_protected_headers);

        $this->encrypter->addRecipient(
            $jwe,
            $encryption_key,
            $this->sender_key
        );

        return $jwe->toCompactJSON(0);
    }
}
