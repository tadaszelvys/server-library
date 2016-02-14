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

interface EncryptionCapabilitiesInterface
{
    /**
     * @return \Jose\Object\JWKSetInterface
     */
    public function getEncryptionPublicKeySet();

    /**
     * @return string[]
     */
    public function getSupportedEncryptionAlgorithms();
}
