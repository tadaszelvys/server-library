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

use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountId;
use OAuth2\Model\UserAccount\UserAccountRepositoryInterface;

class UserAccountRepository implements UserAccountRepositoryInterface
{
    /**
     * @var UserAccount[]
     */
    private $userAccounts = [];

    /**
     * UserAccountRepository constructor.
     */
    public function __construct()
    {
        $this->save(UserAccount::create(
            UserAccountId::create('john.1'),
            [
                'password' => 'doe',
                'user' => 'john',
                'address', [
                    'street_address' => '5 rue Sainte Anne',
                    'region'         => 'Île de France',
                    'postal_code'    => '75001',
                    'locality'       => 'Paris',
                    'country'        => 'France',
                ],
                'name' => 'John Doe',
                'given_name' => 'John',
                'family_name' => 'Doe',
                'middle_name' => 'Jack',
                'nickname' => 'Little John',
                'profile' => 'https://profile.doe.fr/john/',
                'preferred_username' => 'j-d',
                'gender' => 'M',
                'phone_number' => '+0123456789',
                'phone_number_verified' => true,
                'updated_at' => time() - 1000,
                'zoneinfo' => 'Europe/Paris',
                'locale' => 'en',
                'picture' => 'https://www.google.com',
                'amr', ['password' => 'otp'],
                'birthdate' => '1950-01-01',
                'email' => 'root@localhost.com',
                'email_verified' => false,
                'last_login_at' => time() - 100,
                'website' => 'https://john.doe.com',
                'website#fr_fr' => 'https://john.doe.fr',
                'website#fr' => 'https://john.doe.fr',
                'picture#de' => 'https://john.doe.de/picture',
            ]
        ));
    }

    /**
     * @param UserAccount $userAccount
     * @return self
     */
    public function save(UserAccount $userAccount): self
    {
        $this->userAccounts[$userAccount->getId()->getValue()] = $userAccount;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function isPasswordCredentialsValid(UserAccount $user, string $password): bool
    {
        if (!$user instanceof UserAccount || !$user->has('password')) {
            return false;
        }

        return hash_equals($password, $user->get('password'));
    }

    /**
     * {@inheritdoc}
     */
    public function getByUsername(string $username)
    {
        return $this->getByPublicId(UserAccountId::create($username));
    }

    /**
     * {@inheritdoc}
     */
    public function getByPublicId(UserAccountId $publicId)
    {
        return isset($this->userAccounts[$publicId->getValue()]) ? $this->userAccounts[$publicId->getValue()] : null;
    }
}
