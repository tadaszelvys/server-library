<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use Psr\Http\Message\ServerRequestInterface;

/**
 * This extension will help client to override scope policy configuration defined in the server.
 */
interface ScopeExtensionInterface
{
    /**
     * Get available scopes.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return string[] The available scopes depending on the client and the server.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getAvailableScopes(ServerRequestInterface $request = null);

    /**
     * Get the default scopes.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return string[] The default scopes depending on the client and the server.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getDefaultScopes(ServerRequestInterface $request = null);

    /**
     * Get the scope policy.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return string The scope policy depending on the client and the server.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getScopePolicy(ServerRequestInterface $request = null);
}
