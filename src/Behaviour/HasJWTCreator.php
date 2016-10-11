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

use Assert\Assertion;
use Jose\JWTCreatorInterface;

trait HasJWTCreator
{
    /**
     * @var \Jose\JWTCreatorInterface|null
     */
    private $jwt_creator = null;

    /**
     * @return bool
     */
    protected function hasJWTCreator()
    {
        return null !== $this->jwt_creator;
    }

    /**
     * @return \Jose\JWTCreatorInterface
     */
    protected function getJWTCreator()
    {
        Assertion::true($this->hasJWTCreator(), 'The JWT Creator is not available.');

        return $this->jwt_creator;
    }

    /**
     * @param \Jose\JWTCreatorInterface $jwt_creator
     */
    protected function setJWTCreator(JWTCreatorInterface $jwt_creator)
    {
        $this->jwt_creator = $jwt_creator;
    }
}
