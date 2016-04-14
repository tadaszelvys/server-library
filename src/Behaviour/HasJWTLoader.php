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

use Jose\Factory\JWTLoader;

trait HasJWTLoader
{
    /**
     * @var \Jose\Factory\JWTLoader
     */
    private $jwt_loader;

    /**
     * @return \Jose\Factory\JWTLoader
     */
    protected function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \Jose\Factory\JWTLoader $jwt_loader
     */
    private function setJWTLoader(JWTLoader $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;
    }
}
