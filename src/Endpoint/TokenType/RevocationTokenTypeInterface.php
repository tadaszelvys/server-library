<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenType;

use OAuth2\Token\TokenInterface;

interface RevocationTokenTypeInterface extends TokenTypeInterface
{
    /**
     * @param \OAuth2\Token\TokenInterface $token
     */
    public function revokeToken(TokenInterface $token);
}
