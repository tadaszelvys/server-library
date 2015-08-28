<?php

namespace OAuth2\Grant;

use OAuth2\Client\ClientInterface;
use Symfony\Component\HttpFoundation\Request;

interface GrantTypeSupportInterface
{
    /**
     * This function returns the supported grant type.
     *
     * @return string The grant type
     */
    public function getGrantType();

    /**
     * This is the access token endpoint
     * This function checks the request and returns information to issue an access token.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     * @param \OAuth2\Client\ClientInterface            $client  The client
     *
     * @return \OAuth2\Grant\GrantTypeResponseInterface
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function grantAccessToken(Request $request, ClientInterface $client);
}
