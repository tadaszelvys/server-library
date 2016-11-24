<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenIntrospection;

use Psr\Http\Message\ServerRequestInterface;

final class TokenIntrospectionPostEndpoint extends TokenIntrospectionEndpoint
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string|null                              $token
     * @param string|null                              $tokenTypeHint
     */
    protected function getParameters(ServerRequestInterface $request, &$token, &$tokenTypeHint)
    {
        $params = $request->getParsedBody();
        foreach (['token', 'tokenTypeHint'] as $key) {
            $$key = array_key_exists($key, $params) ? $params[$key] : null;
        }
    }
}
