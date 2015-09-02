<?php

namespace OAuth2\Endpoint;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface RevocationEndpointInterface
{
    /**
     * This method will try to:
     *   - find the client in the request
     *   - find the token (access token or refresh token) using type hint if available
     *   - revoke the token and token exists. For confidential clients, authentication is required.
     *   - in any case, return an HTTP response with code 200.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request  The request
     * @param \Psr\Http\Message\ResponseInterface      $response The response
     */
    public function revoke(ServerRequestInterface $request, ResponseInterface &$response);
}
