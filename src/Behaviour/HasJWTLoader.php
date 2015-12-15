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

use OAuth2\Util\JWTLoader;

trait HasJWTLoader
{
    /**
     * @var \OAuth2\Util\JWTLoader
     */
    private $jwt_loader;

    /**
     * @return \OAuth2\Util\JWTLoader
     */
    protected function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \OAuth2\Util\JWTLoader $jwt_loader
     */
    private function setJWTLoader(JWTLoader $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;
    }
}
