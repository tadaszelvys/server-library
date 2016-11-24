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

use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use Psr\Http\Message\ServerRequestInterface;

interface GrantTypeInterface
{
    /**
     * This function returns the list of associated response types.
     *
     * @return string[]
     */
    public function getAssociatedResponseTypes(): array;

    /**
     * This function returns the supported grant type.
     *
     * @return string The grant type
     */
    public function getGrantType(): string;

    /**
     * This function checks the request and returns information to issue an access token.
     *
     * @param ServerRequestInterface $request             The request
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     *
     * @throws OAuth2Exception
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response);

    /**
     * @param ServerRequestInterface $request
     * @param Client           $client
     * @param GrantTypeResponseInterface $grant_type_response
     *
     * @throws OAuth2Exception
     */
    public function grantAccessToken(ServerRequestInterface $request, Client $client, GrantTypeResponseInterface &$grant_type_response);
}
