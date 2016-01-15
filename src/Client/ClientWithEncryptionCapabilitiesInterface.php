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

interface ClientWithEncryptionCapabilitiesInterface extends RegisteredClientInterface
{
    /**
     * @param array $key
     */
    public function setEncryptionPublicKey(array $key);

    /**
     * @return array
     */
    public function getSignaturePublicKey();

    /**
     * @param string $encryption_algorithm
     */
    public function setEncryptionAlgorithm($encryption_algorithm);

    /**
     * @return string
     */
    public function getEncryptionAlgorithm();
}
