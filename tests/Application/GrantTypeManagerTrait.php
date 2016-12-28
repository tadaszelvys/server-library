<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Application;

use OAuth2\Grant\GrantTypeManager;
use OAuth2\Grant\GrantTypeManagerInterface;

trait GrantTypeManagerTrait
{
    /**
     * @var null|GrantTypeManagerInterface
     */
    private $grantTypeManager = null;

    /**
     * @return GrantTypeManagerInterface
     */
    public function getGrantTypeManager(): GrantTypeManagerInterface
    {
        if (null === $this->grantTypeManager) {
            $this->grantTypeManager = new GrantTypeManager();
        }

        return $this->grantTypeManager;
    }
}
