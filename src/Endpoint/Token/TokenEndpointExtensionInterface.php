<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Token;

use Psr\Http\Message\ServerRequestInterface;

interface TokenEndpointExtensionInterface
{
    /**
     * @param ServerRequestInterface $serverRequest
     * @param array $data
     * @param \Closure $next
     * @return array
     */
    public function process(ServerRequestInterface $serverRequest, array $data, \Closure $next): array;
}
