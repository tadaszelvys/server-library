<?php

namespace OAuth2\Token;

use Psr\Http\Message\ServerRequestInterface;

interface AccessTokenTypeManagerInterface
{
    /**
     * Tries to find an access token in the request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     *
     * @return \OAuth2\Token\AccessTokenInterface|null The access token
     */
    public function findAccessToken(ServerRequestInterface $request);
}
