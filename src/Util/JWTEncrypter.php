<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Util;

use Jose\EncrypterInterface;
use Jose\JSONSerializationModes;
use Jose\Object\EncryptionInstruction;
use Jose\Object\JWK;

final class JWTEncrypter
{
    /**
     * @var \Jose\EncrypterInterface
     */
    private $encrypter;

    /**
     * @var null|\Jose\Object\JWKInterface
     */
    private $encryption_key = null;

    /**
     * JWTEncrypter constructor.
     *
     * @param \Jose\EncrypterInterface $encrypter
     * @param array                    $encryption_key
     */
    public function __construct(EncrypterInterface $encrypter, array $encryption_key)
    {
        $this->encrypter = $encrypter;
        if (!empty($encryption_key)) {
            $this->encryption_key = new JWK($encryption_key);
        }
    }

    /**
     * @param string $payload
     * @param array  $protected_headers
     * @param array  $sender_key
     *
     * @return string
     */
    public function encrypt($payload, array $protected_headers, array $sender_key = [])
    {
        if (null === $this->encryption_key) {
            return $payload;
        }
        $sender_key = empty($sender_key) ? null : new JWK($sender_key);
        $instruction = new EncryptionInstruction($this->encryption_key, $sender_key);

        return $this->encrypter->encrypt(
            $payload,
            [$instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            $protected_headers
        );
    }
}
