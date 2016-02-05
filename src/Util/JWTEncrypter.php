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
use Jose\Object\JWKInterface;

final class JWTEncrypter
{
    /**
     * @var \Jose\EncrypterInterface
     */
    private $encrypter;

    /**
     * @var \Jose\Object\JWKInterface
     */
    private $encryption_key = null;

    /**
     * JWTEncrypter constructor.
     *
     * @param string                    $key_encryption_algorithm
     * @param string                    $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface $encryption_key
     */
    public function __construct($key_encryption_algorithm, $content_encryption_algorithm, JWKInterface $encryption_key)
    {
        $this->encrypter = EncrypterFactory::createEncrypter([$key_encryption_algorithm, $content_encryption_algorithm]);
        $this->encryption_key = $encryption_key;
    }

    /**
     * @param string                    $payload
     * @param array                     $protected_headers
     * @param \Jose\Object\JWKInterface $sender_key
     *
     * @return string
     */
    public function encrypt($payload, array $protected_headers, JWKInterface $sender_key = null)
    {
        if (null === $this->encryption_key) {
            return $payload;
        }

        $jwe = JWEFactory::createJWE($payload, $protected_headers);

        $this->encrypter->addRecipient(
            $jwe,
            $this->encryption_key,
            $sender_key
        );

        return $jwe->toCompactJSON(0);
    }
}
