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

interface ClientWithSignatureCapabilitiesInterface extends ConfidentialClientInterface
{
    /**
     * @param array $key_set
     */
    public function setSignaturePublicKeySet(array $key_set);

    /**
     * @return array
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
