<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\User;

interface UserManagerInterface
{
    /**
     * Check if the end-user password is valid.
     *
     * @param \OAuth2\User\UserInterface $user     The end-user
     * @param string                     $password Password
     *
     * @return bool
     */
    public function checkUserPasswordCredentials(UserInterface $user, $password);

    /**
     * Get the end-user with the specified Username.
     *
     * @param string $username Username
     *
     * @return \OAuth2\User\UserInterface|null
     */
    public function getUserByUsername($username);

    /**
     * Get the end-user with the specified public ID.
     *
     * @param string $public_id Public ID
     *
     * @return \OAuth2\User\UserInterface|null
     */
    public function getUserByPublicId($public_id);

    /**
     * Get the end-user with the specified username.
     *
     * @param string $resource Resource
     *
     * @return \OAuth2\User\UserInterface|null
     */
    public function getUserFromResource($resource);
}
