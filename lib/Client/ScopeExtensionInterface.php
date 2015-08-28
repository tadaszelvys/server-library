<?php

namespace OAuth2\Client;

use Symfony\Component\HttpFoundation\Request;

/**
 * This extension will help client to override scope policy configuration defined in the server.
 */
interface ScopeExtensionInterface
{
    /**
     * Get available scopes.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return string[] The available scopes depending on the client and the server.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getAvailableScopes(Request $request = null);

    /**
     * Get the default scopes.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return string[] The default scopes depending on the client and the server.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getDefaultScopes(Request $request = null);

    /**
     * Get the scope policy.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return string The scope policy depending on the client and the server.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     */
    public function getScopePolicy(Request $request = null);
}
