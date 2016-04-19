<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use Jose\JWTLoader;

trait HasJWTLoader
{
    /**
     * @var \Jose\JWTLoader
     */
    private $jwt_loader;

    /**
     * @return \Jose\JWTLoader
     */
    protected function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \Jose\JWTLoader $jwt_loader
     */
    private function setJWTLoader(JWTLoader $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;
    }
}
