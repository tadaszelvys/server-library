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

use Psr\Http\Message\ServerRequestInterface;

interface AccessTokenTypeManagerInterface
{
    /**
     * Tries to find an access token in the request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface    $request           The request.
     * @param \OAuth2\Token\AccessTokenTypeInterface|null $access_token_type
     *
     * @return string|null The access token
     */
    public function findAccessToken(ServerRequestInterface $request, AccessTokenTypeInterface &$access_token_type = null);

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
     * @return \OAuth2\Token\AccessTokenTypeInterface
     */
    public function getDefaultAccessTokenType();
}
