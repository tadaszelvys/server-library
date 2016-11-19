<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientConfiguration;

use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Client\ClientInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface ClientConfigurationEndpointInterface
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     * @param \OAuth2\Client\ClientInterface           $client
     */
    public function handle(ServerRequestInterface $request, ResponseInterface &$response, ClientInterface $client);

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
