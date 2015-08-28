<?php

namespace OAuth2\Token;

use Symfony\Component\HttpFoundation\Request;

interface AccessTokenTypeManagerInterface
{
    /**
     * Tries to find an access token in the request.
     *
     * @param Request $request The request.
     *
     * @return \OAuth2\Token\AccessTokenInterface|null The access token
     */
    public function findAccessToken(Request $request);
}
