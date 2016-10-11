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

trait HasIssuer
{
    /**
     * @var string|null
     */
    private $issuer = null;

    /**
     * @return bool
     */
    protected function hasIssuer()
    {
        return null !== $this->issuer;
    }

    /**
     * @return string
     */
    protected function getIssuer()
    {
        Assertion::true($this->hasIssuer(), 'The issuer is not available.');

        return $this->issuer;
    }

    /**
     * @param string $issuer
     */
    protected function setIssuer($issuer)
    {
        Assertion::string($issuer);
        $this->issuer = $issuer;
    }
}
