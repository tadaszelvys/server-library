<?php

namespace OAuth2\Endpoint;

use Psr\Http\Message\ResponseInterface;

interface AuthorizationEndpointInterface
{
    /**
     * @param \OAuth2\Endpoint\Authorization $authorization
     * @param \Psr\Http\Message\ResponseInterface     $response
     */
    public function authorize(Authorization $authorization, ResponseInterface &$response);
}
