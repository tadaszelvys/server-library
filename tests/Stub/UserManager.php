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

use OAuth2\User\UserInterface;
use OAuth2\User\UserManagerInterface;

class UserManager implements UserManagerInterface
{
    /**
     * @var \OAuth2\User\UserInterface[]
     */
    private $users = [];

    public function __construct()
    {
        $user1 = new User('user1', 'password1');
        $user1->set('address', [
            'street_address' => '5 rue Sainte Anne',
            'region'         => 'Île de France',
            'postal_code'    => '75001',
            'locality'       => 'Paris',
            'country'        => 'France',
        ]);
        $user1->set('amr', ['password', 'otp']);
        $user1->set('birthdate', '1950-01-01');
        $user1->set('email', 'root@localhost.com');
        $user1->set('email_verified', false);
        $user1->set('last_login_at', time() - 100);

        $user2 = new User('user2', 'password2');
        $user2->set('last_login_at', time() - 1000);

        $this->users['user1'] = $user1;
        $this->users['user2'] = $user2;
    }

    /**
     * {@inheritdoc}
     */
    public function checkUserPasswordCredentials(UserInterface $resource_owner, $password)
    {
        if (!$resource_owner instanceof User) {
            return false;
        }

        return hash_equals($password, $resource_owner->getPassword());
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($public_id)
    {
        return isset($this->users[$public_id]) ? $this->users[$public_id] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserFromResource($resource)
    {
        $server = 'my-service.com:9000';
        $length = mb_strlen($server, 'utf-8');
        if ('https://'.$server.'/+' === mb_substr($resource, 0, $length+10, 'utf-8')) {
            $resource = mb_substr($resource, $length+10, null, 'utf-8');
        }
        if ('acct:' === mb_substr($resource, 0, 5, 'utf-8') && '@'.$server === mb_substr($resource, -($length+1), null, 'utf-8')) {
            $resource = mb_substr($resource, 5, -($length+1), 'utf-8');
        }
        
        return isset($this->users[$resource]) ? $this->users[$resource] : null;
    }
}
