<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Jose\Object\JWSInterface;

class JWTAccessToken extends AccessToken implements JWTAccessTokenInterface
{
    /**
     * @var \Jose\Object\JWSInterface
     */
    private $jws = null;

    /**
     * {@inheritdoc}
     */
    public function setJWS(JWSInterface $jws)
    {
        $this->jws = $jws;
    }

    /**
     * {@inheritdoc}
     */
    public function getJWS()
    {
        return $this->jws;
    }
}
