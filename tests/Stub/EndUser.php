<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\EndUser\IssueRefreshTokenExtensionInterface;

class EndUser implements EndUserInterface, IssueRefreshTokenExtensionInterface
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
     * @var string
     */
    private $public_id;

    /**
     * @param string $username
     * @param string $password
     */
    public function __construct($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
        $this->public_id = base_convert(sha1(uniqid(mt_rand(), true)), 16, 36);
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'end-user';
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicId()
    {
        return $this->public_id;
    }

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
    public function isRefreshTokenIssuanceAllowed(ClientInterface $client, $grant_type)
    {
        return $client instanceof ConfidentialClientInterface;
    }
}
