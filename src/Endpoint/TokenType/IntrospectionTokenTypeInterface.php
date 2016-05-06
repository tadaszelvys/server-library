<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenType;

use OAuth2\Client\ClientInterface;
use OAuth2\Token\TokenInterface;

interface IntrospectionTokenTypeInterface extends TokenTypeInterface
{
    /**
     * @param \OAuth2\Token\TokenInterface   $token
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return array
     */
    public function introspectToken(TokenInterface $token, ClientInterface $client);
}
