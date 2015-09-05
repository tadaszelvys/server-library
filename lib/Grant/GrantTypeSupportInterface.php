<?php

namespace OAuth2\Grant;

use OAuth2\Client\ClientInterface;
use Psr\Http\Message\ServerRequestInterface;

interface GrantTypeSupportInterface
{
    /**
     * This function returns the supported grant type.
     *
     * @return string The grant type
     */
    public function getGrantType();

    /**
     * This function checks the request and returns information to issue an access token.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response);
}
