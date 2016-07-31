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
use Assert\Assertion;

/**
 * Class UserTrait.
 */
trait UserTrait
{
    /**
     * @var int|null
     */
    protected $last_login_at = null;

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
        Assertion::nullOrInteger($last_login_at);
        $this->last_login_at = $last_login_at;
    }
}
