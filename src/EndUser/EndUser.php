<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\EndUser;

use OAuth2\ResourceOwner\ResourceOwner;

/**
 * This interface must be implemented by end-user classes.
 */
class EndUser extends ResourceOwner implements EndUserInterface
{
    protected $last_login_at = null;

    public function __construct()
    {
        parent::__construct();
        $this->setType('end_user');
    }

    /**
     * {@inheritdoc}
     */
    public function getLastLoginAt()
    {
        return $this->last_login_at;
    }

    /**
     * {@inheritdoc}
     */
    public function setLastLoginAt($last_login_at)
    {
        $this->last_login_at = $last_login_at;
    }
}
