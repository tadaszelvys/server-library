<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\GrantType;

use OAuth2\Endpoint\Token\GrantTypeData;
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
     * This function checks the request.
     *
     * @param ServerRequestInterface $request The request
     *
     * @throws OAuth2Exception
     */
    public function checkTokenRequest(ServerRequestInterface $request);

    /**
     * This function checks the request and returns information to issue an access token.
     *
     * @param ServerRequestInterface                   $request             The request
     * @param GrantTypeData $grantTypeResponse
     * @return GrantTypeData
     *
     * @throws OAuth2Exception
     */
    public function prepareTokenResponse(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData;

    /**
     * @param ServerRequestInterface     $request
     * @param GrantTypeData $grantTypeResponse
     * @return GrantTypeData
     *
     * @throws OAuth2Exception
     */
    public function grant(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData;
}
