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
     * @var string
     */
    private $issuer;

    /**
     * @return string
     */
    private function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * @param string $issuer
     */
    private function setIssuer($issuer)
    {
        Assertion::string($issuer);
        $this->issuer = $issuer;
    }
}
