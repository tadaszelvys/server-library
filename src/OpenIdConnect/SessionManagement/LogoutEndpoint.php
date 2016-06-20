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

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class LogoutEndpoint implements LogoutEndpointInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(ServerRequestInterface $server, ResponseInterface &$response)
    {
        /*
         * This method is not supported as the id_token_hint is not yet supported
         */
        $response = $response->withStatus(403);
    }
}
