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

use Jose\JWTCreatorInterface;

trait HasJWTCreator
{
    /**
     * @var \Jose\JWTCreatorInterface
     */
    private $jwt_creator;

    /**
     * @return \Jose\JWTCreatorInterface
     */
    private function getJWTCreator()
    {
        return $this->jwt_creator;
    }

    /**
     * @param \Jose\JWTCreatorInterface $jwt_creator
     */
    private function setJWTCreator(JWTCreatorInterface $jwt_creator)
    {
        $this->jwt_creator = $jwt_creator;
    }
}
