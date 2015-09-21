<?php

namespace OAuth2\Token;

use Psr\Http\Message\ServerRequestInterface;

interface AccessTokenTypeManagerInterface
{
    /**
     * Tries to find an access token in the request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface    $request           The request.
     * @param \OAuth2\Token\AccessTokenTypeInterface|null $access_token_type
     *
     * @return string|null The access token
     */
    public function findAccessToken(ServerRequestInterface $request, AccessTokenTypeInterface &$access_token_type = null);

    /**
     * @return \OAuth2\Token\AccessTokenTypeInterface
     */
    public function getDefaultAccessTokenType();
}
