<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientRegistration;

use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface ClientRegistrationEndpointInterface
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     */
    public function register(ServerRequestInterface $request, ResponseInterface &$response);

    /**
     * @return bool
     */
    public function isInitialAccessTokenSupported();

    /**
     * @return bool
     */
    public function isInitialAccessTokenRequired();

    public function allowRegistrationWithoutInitialAccessToken();

    public function disallowRegistrationWithoutInitialAccessToken();

    /**
     * @param \OAuth2\Endpoint\ClientRegistration\InitialAccessTokenManagerInterface $initial_access_token_manage
     */
    public function enableInitialAccessTokenSupport(InitialAccessTokenManagerInterface $initial_access_token_manage);

    /**
     * @param \Jose\JWTLoaderInterface     $jwt_loader
     * @param \Jose\Object\JWKSetInterface $signature_key_set
     */
    public function enableSoftwareStatementSupport(JWTLoaderInterface $jwt_loader, JWKSetInterface $signature_key_set);

    /**
     * @return bool
     */
    public function isSoftwareStatementSupported();

    /**
     * @return bool
     */
    public function isSoftwareStatementRequired();

    public function allowRegistrationWithoutSoftwareStatement();

    public function disallowRegistrationWithoutSoftwareStatement();
}
