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
        $address1 = new Address();
        $address1->setCountry('France');
        $address1->setLocality('Paris');
        $address1->setPostalCode('75001');
        $address1->setRegion('Île de France');
        $address1->setStreetAddress('5 rue Sainte Anne');

        $user1 = new EndUser('user1', 'password1');
        $user1->setAddress($address1);
        $user1->setAuthenticationMethodsReferences(['password', 'otp']);
        $user1->setBirthdate('1950-01-01');
        $user1->setEmail('root@localhost.com');
        $user1->setEmailVerified(false);
        $user1->setLastLoginAt(time() - 100);

        $user2 = new EndUser('user2', 'password2');
        $user2->setLastLoginAt(time() - 1000);

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
