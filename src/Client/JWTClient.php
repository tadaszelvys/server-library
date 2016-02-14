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

class JWTClient extends ConfidentialClient implements SignatureCapabilitiesInterface, EncryptionCapabilitiesInterface
{
    use JWTClientTrait;

    /**
     * JWTClient constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->setType('jwt_client');
    }
}
