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

use Jose\Factory\JWSFactory;
use Jose\Factory\SignerFactory;
use Jose\Object\JWKInterface;

final class JWTSigner
{
    /**
     * @var \Jose\SignerInterface
     */
    private $signer;

    /**
     * @var \Jose\Object\JWKInterface
     */
    private $signature_key;

    /**
     * JWTSigner constructor.
     *
     * @param string                    $signature_algorithm
     * @param \Jose\Object\JWKInterface $signature_key
     */
    public function __construct($signature_algorithm, JWKInterface $signature_key)
    {
        $this->signer = SignerFactory::createSigner([$signature_algorithm]);
        $this->signature_key = $signature_key;
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
        $jws = JWSFactory::createJWS($claims);

        $this->signer->addSignature(
            $jws,
            $this->signature_key,
            $protected_headers
        );

        return $jws->toCompactJSON(0);
    }
}
