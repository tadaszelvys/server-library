<?php

namespace OAuth2\Test\Stub;

use OAuth2\EndUser\EndUserInterface;
use OAuth2\EndUser\EndUserManagerInterface;

class EndUserManager implements EndUserManagerInterface
{
    /**
     * @var \OAuth2\EndUser\EndUserInterface[]
     */
    private $users = [];

    public function __construct()
    {
        $user1 = new EndUser('user1', 'password1');
        $user1->setLastLoginAt(time()-100);

        $user2 = new EndUser('user2', 'password2');
        $user2->setLastLoginAt(time()-1000);

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
    public function getEndUser($public_id)
    {
        return isset($this->users[$public_id]) ? $this->users[$public_id] : null;
    }
}
