<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\EndUser\EndUser as BaseEndUser;
use OAuth2\EndUser\IssueRefreshTokenExtensionInterface;

class EndUser extends BaseEndUser implements IssueRefreshTokenExtensionInterface
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
