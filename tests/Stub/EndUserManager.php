<?php

namespace OAuth2\Test\Stub;

use OAuth2\EndUser\EndUserInterface;
use OAuth2\EndUser\EndUserManagerInterface;

class EndUserManager implements EndUserManagerInterface
{
    /**
     * @var \OAuth2\EndUser\EndUserInterface[]
     */
    private $users = array();

    public function __construct()
    {
        $user1 = new EndUser('user1', 'password1');
        $user2 = new EndUser('user2', 'password2');

        $this->users['user1'] = $user1;
        $this->users['user2'] = $user2;
    }

    /**
     * {@inheritdoc}
     */
    public function checkEndUserPasswordCredentials(EndUserInterface $resource_owner, $password)
    {
        if (!$resource_owner instanceof EndUser) {
            return false;
        }

        return $resource_owner->getPassword() === $password;
    }

    /**
     * {@inheritdoc}
     */
    public function getEndUser($username)
    {
        return isset($this->users[$username]) ? $this->users[$username] : null;
    }
}
