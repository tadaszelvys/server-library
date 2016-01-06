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

interface JWTAccessTokenInterface extends AccessTokenInterface
{
    /**
     * @param \Jose\Object\JWSInterface $jws
     */
    public function setJWS(JWSInterface $jws);

    /**
     * @return \Jose\Object\JWSInterface
     */
    public function getJWS();
}
