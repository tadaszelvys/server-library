<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Token;

use OAuth2\Model\AccessToken\AccessToken;
use Psr\Http\Message\ServerRequestInterface;

interface TokenEndpointExtensionInterface
{
    /**
     * @param ServerRequestInterface $request
     * @param GrantTypeData          $tokenResponse
     * @param callable               $next
     *
     * @return AccessToken
     */
    public function process(ServerRequestInterface $request, GrantTypeData $tokenResponse, callable $next): AccessToken;
}
