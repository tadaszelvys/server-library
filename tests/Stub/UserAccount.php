<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Assert\Assertion;
use OAuth2\UserAccount\UserAccount as BaseUserAccount;

final class UserAccount extends BaseUserAccount
{
    /**
     * @var string
     */
    private $user_public_id;

    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $password;

    /**
     * @var int|null
     */
    protected $last_login_at = null;

    /**
     * UserAccount constructor.
     *
     * @param string $username
     * @param string $password
     * @param string $user_public_id
     */
    public function __construct($username, $password, $user_public_id)
    {
        parent::__construct();
        $this->setPublicId($username);
        $this->username = $username;
        $this->password = $password;
        $this->user_public_id = $user_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserPublicId()
    {
        return $this->user_public_id;
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
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
        Assertion::nullOrInteger($last_login_at);
        $this->last_login_at = $last_login_at;
    }
}
