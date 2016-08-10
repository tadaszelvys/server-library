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

use OAuth2\Client\ClientInterface;
use OAuth2\UserAccount\IssueRefreshTokenExtensionInterface;
use OAuth2\UserAccount\UserAccount as BaseUserAccount;

final class UserAccount extends BaseUserAccount implements IssueRefreshTokenExtensionInterface
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $password;

    /**
     * UserAccount constructor.
     *
     * @param string $username
     * @param string $password
     */
    public function __construct($username, $password)
    {
        parent::__construct();
        $this->setPublicId($username);
        $this->username = $username;
        $this->password = $password;
    }

    public function getUserAccountname()
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
    public function isRefreshTokenIssuanceAllowed(ClientInterface $client, $grant_type)
    {
        return !$client->isPublic();
    }
}
