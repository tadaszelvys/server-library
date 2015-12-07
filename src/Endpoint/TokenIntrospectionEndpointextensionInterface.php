<?php

namespace OAuth2\Endpoint;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface TokenIntrospectionEndpointExtensionInterface
{
    /**
     * @param \OAuth2\Token\AccessTokenInterface|\OAuth2\Token\RefreshTokenInterface $token
     *
     * @return array
     */
    public function getTokenInformation($token);
}
