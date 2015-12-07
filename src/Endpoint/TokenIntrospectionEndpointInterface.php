<?php

namespace OAuth2\Endpoint;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface TokenIntrospectionEndpointInterface
{
    /**
     * @param \OAuth2\Endpoint\TokenIntrospectionEndpointExtensionInterface $extension
     */
    public function addExtension(TokenIntrospectionEndpointExtensionInterface $extension);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     */
    public function introspect(ServerRequestInterface $request, ResponseInterface &$response);
}
