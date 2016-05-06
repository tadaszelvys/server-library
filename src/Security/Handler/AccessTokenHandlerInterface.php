<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Security\Handler;

interface AccessTokenHandlerInterface
{
    /**
     * @param string $token
     *
     * @return null|\OAuth2\Token\AccessTokenInterface
     */
    public function getAccessToken($token);
}
