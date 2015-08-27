<?php

namespace OAuth2\Endpoint;

use Symfony\Component\HttpFoundation\Request;

interface RevocationEndpointInterface
{
    /**
     * This method will try to:
     *   - find the client in the request
     *   - find the token (access token or refresh token) using type hint if available
     *   - revoke the token and token exists. For confidential clients, authentication is required.
     *   - in any case, return an HTTP response with code 200.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function revoke(Request $request);
}
