<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Client\ClientInterface;
use Psr\Http\Message\ServerRequestInterface;

interface GrantTypeInterface
{
    /**
     * This function returns the supported grant type.
     *
     * @return string The grant type
     */
    public function getGrantType();

    /**
     * @param array $request_parameters
     *
     * @return bool
     */
    public function isSupported(array $request_parameters);

    /**
     * This function checks the request and returns information to issue an access token.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request             The request
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
