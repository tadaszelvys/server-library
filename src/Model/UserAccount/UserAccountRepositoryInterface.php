<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\UserAccount;

interface UserAccountRepositoryInterface
{
    /**
     * Check if the user account password is valid.
     *
     * @param UserAccount $user     The user account
     * @param string      $password Password
     *
     * @return bool
     */
    public function isPasswordCredentialsValid(UserAccount $user, string $password): bool;

    /**
     * Get the user account with the specified User Account Name.
     *
     * @param string $username User Account Name
     *
     * @return UserAccount|null
     */
    public function findByUsername(string $username);

    /**
     * Get the user account with the specified public ID.
     *
     * @param UserAccountId $publicId Public ID
     *
     * @return UserAccount|null
     */
    public function find(UserAccountId $publicId);
}
