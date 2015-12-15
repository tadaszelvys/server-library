<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use OAuth2\Util\JWTSigner;

trait HasJWTSigner
{
    /**
     * @var \OAuth2\Util\JWTSigner
     */
    private $jwt_signer;

    /**
     * @return \OAuth2\Util\JWTSigner
     */
    protected function getJWTSigner()
    {
        return $this->jwt_signer;
    }

    /**
     * @param \OAuth2\Util\JWTSigner $jwt_signer
     */
    private function setJWTSigner(JWTSigner $jwt_signer)
    {
        $this->jwt_signer = $jwt_signer;
    }
}
