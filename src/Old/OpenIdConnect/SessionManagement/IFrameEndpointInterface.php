<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\SessionManagement;

use Psr\Http\Message\ServerRequestInterface;

interface IFrameEndpointInterface
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $server
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function handle(ServerRequestInterface $server);
}
