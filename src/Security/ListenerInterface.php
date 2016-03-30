<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Security;

use Psr\Http\Message\ServerRequestInterface;

interface ListenerInterface
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    public function handle(ServerRequestInterface $request);
}
