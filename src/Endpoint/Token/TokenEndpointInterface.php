<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Token;

use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface TokenEndpointInterface
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request  The request
     * @param \Psr\Http\Message\ResponseInterface      $response The response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface If an error occurred
     */
    public function getAccessToken(ServerRequestInterface $request, ResponseInterface &$response);

    /**
     * @param \OAuth2\Token\RefreshTokenManagerInterface $refresh_token_manager
     */
    public function enableRefreshTokenSupport(RefreshTokenManagerInterface $refresh_token_manager);

    /**
     * @param \OAuth2\Scope\ScopeManagerInterface $scope_manager
     *
     * @return mixed
     */
    public function enableScopeSupport(ScopeManagerInterface $scope_manager);

    /**
     * @param \OAuth2\Endpoint\Token\TokenEndpointExtensionInterface $token_endpoint_extension
     */
    public function addTokenEndpointExtension(TokenEndpointExtensionInterface $token_endpoint_extension);
}
