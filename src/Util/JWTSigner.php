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

use Jose\JSONSerializationModes;
use Jose\Object\JWK;
use Jose\Object\SignatureInstruction;
use Jose\SignerInterface;

final class JWTSigner
{
    /**
     * @var \Jose\SignerInterface
     */
    protected $signer;

    /**
     * @var \Jose\Object\JWKInterface
     */
    protected $signature_key;

    /**
     * JWTSigner constructor.
     *
     * @param \Jose\SignerInterface $signer
     * @param array                 $signature_key
     */
    public function __construct(SignerInterface $signer, array $signature_key)
    {
        $this->signer = $signer;
        $this->signature_key = new JWK($signature_key);
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    public function getSignatureKey()
    {
        return $this->signature_key;
    }

    /**
     * @param array $claims
     * @param array $protected_headers
     *
     * @return string
     */
    public function sign(array $claims, array $protected_headers)
    {
        $instruction = new SignatureInstruction($this->signature_key, $protected_headers);

        return $this->signer->sign(
            $claims,
            [$instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION
        );
    }
}
