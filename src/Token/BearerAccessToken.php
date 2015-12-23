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


class BearerAccessToken implements AccessTokenTypeInterface
{
    /**
     * {@inheritdoc}
     */
    public function updateAccessToken(AccessTokenInterface &$token)
    {
        $token->setTokenType('Bearer');
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeName()
    {
        return 'bearer';
    }
}
