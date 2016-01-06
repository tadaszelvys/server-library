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

use OAuth2\Token\TokenInterface;
use OAuth2\Token\TokenUpdaterInterface;

class FooBarAccessTokenUpdater implements TokenUpdaterInterface
{
    /**
     * {@inheritdoc}
     */
    public function updateToken(TokenInterface &$token)
    {
        $token->setParameter('foo', 'bar');
    }
}
