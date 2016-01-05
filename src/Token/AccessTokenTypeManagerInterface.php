<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

interface AccessTokenTypeManagerInterface
{
    /**
     * @param \OAuth2\Token\AccessTokenTypeInterface $access_token_type
     * @param bool                                   $default
     */
    public function addAccessTokenType(AccessTokenTypeInterface $access_token_type, $default = false);

    /**
     * @return \OAuth2\Token\AccessTokenTypeInterface[]
     */
    public function getAccessTokenTypes();

    /**
     * @param string $token_type_name
     *
     * @return bool
     */
    public function hasAccessTokenType($token_type_name);

    /**
     * @param string $token_type_name
     *
     * @return \OAuth2\Token\AccessTokenTypeInterface
     */
    public function getAccessTokenType($token_type_name);

    /**
     * @return \OAuth2\Token\AccessTokenTypeInterface
     */
    public function getDefaultAccessTokenType();
}
