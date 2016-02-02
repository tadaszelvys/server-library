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

use Jose\Object\JWKSetInterface;

interface ClientWithSignatureCapabilitiesInterface extends ConfidentialClientInterface
{
    /**
     * @param \Jose\Object\JWKSetInterface $key_set
     *
     * @return mixed
     */
    public function setSignaturePublicKeySet(JWKSetInterface $key_set);

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    public function getSignaturePublicKeySet();

    /**
     * @param string[] $allowed_signature_algorithms
     */
    public function setAllowedSignatureAlgorithms(array $allowed_signature_algorithms);

    /**
     * @return string[]
     */
    public function getAllowedSignatureAlgorithms();
}
