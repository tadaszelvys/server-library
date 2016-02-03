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

use OAuth2\Grant\NoneResponseTypeListenerInterface;
use OAuth2\Token\AccessTokenInterface;

class NoneListener implements NoneResponseTypeListenerInterface
{
    /**
     * @var \OAuth2\Token\AccessTokenInterface[]
     */
    private $access_tokens = [];

    /**
     * [@inheritdoc}
     */
    public function call(AccessTokenInterface $access_token)
    {
        $this->access_tokens[] = $access_token;
    }

    /**
     * @return \OAuth2\Token\AccessTokenInterface[]
     */
    public function getAccessTokens()
    {
        return $this->access_tokens;
    }
}
