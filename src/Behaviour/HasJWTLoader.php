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

use Jose\JWTLoaderInterface;

trait HasJWTLoader
{
    /**
     * @var \Jose\JWTLoaderInterface
     */
    private $jwt_loader;

    /**
     * @return \Jose\JWTLoaderInterface
     */
    private function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \Jose\JWTLoaderInterface $jwt_loader
     */
    private function setJWTLoader(JWTLoaderInterface $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;
    }
}
