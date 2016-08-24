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

/**
 * This interface must be implemented by end-user classes.
 */
interface UserInterface
{
    /**
     * @return \OAuth2\UserAccount\UserAccountInterface[]
     */
    public function getAccounts();

    /**
     * Get resource owner identifier.
     * The ID is a string that represents the resource owner and is unique to the authorization server.
     *
     * This ID and IDs from user's accounts must be different.
     *
     * @return string ID of the resource owner
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.2
     */
    public function getPublicId();
}
