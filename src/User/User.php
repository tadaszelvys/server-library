<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\User;

use OAuth2\ResourceOwner\ResourceOwner;

/**
 * This interface must be implemented by end-user classes.
 */
class User extends ResourceOwner implements UserInterface
{
    use UserTrait;

    /**
     * User constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->setType('user');
    }
}
