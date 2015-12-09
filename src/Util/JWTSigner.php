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
use Jose\JWKManager;
use Jose\SignatureInstruction;
use Jose\SignerInterface;

final class JWTSigner
{
    /**
     * @var \Jose\SignerInterface
     */
    protected $jwt_signer;

    /**
     * @var \Jose\JWKInterface
     */
    protected $signature_key;

    /**
     * @return \Jose\JWKManagerInterface
     */
    public function getKeyManager()
    {
        return new JWKManager();
    }

    /**
     * @return \Jose\SignerInterface
     */
    public function getJWTSigner()
    {
        return $this->jwt_signer;
    }

    /**
     * @param \Jose\SignerInterface $jwt_signer
     *
     * @return self
     */
    public function setJWTSigner(SignerInterface $jwt_signer)
    {
        $this->jwt_signer = $jwt_signer;

        return $this;
    }

    /**
     * @return \Jose\JWKInterface
     */
    public function getSignatureKey()
    {
        return $this->signature_key;
    }

    /**
     * @param array $signature_key
     *
     * @return self
     */
    public function setSignatureKey(array $signature_key)
    {
        $this->signature_key = $this->getKeyManager()->createJWK($signature_key);

        return $this;
    }

    /**
     * @param array $claims
     * @param array $protected_headers
     *
     * @return string
     */
    public function sign(array $claims, array $protected_headers)
    {
        $instruction = new SignatureInstruction($this->getSignatureKey(), $protected_headers);

        $result = $this->getJWTSigner()->sign($claims, [$instruction], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
        if (!is_string($result)) {
            throw new \RuntimeException('Unable to sign claims.');
        }

        return $result;
    }
}
