<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenEndpointAuthMethod;

use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use Psr\Http\Message\ServerRequestInterface;

interface TokenEndpointAuthMethodInterface
{
    /**
     * @return string[]
     */
    public function getSupportedAuthenticationMethods(): array;

    /**
     * Find a client using the request.
     * If the client is confidential, the client credentials must be checked.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request            The request
     * @param mixed                                    $client_credentials The client credentials found in the request
     *
     * @return null|ClientId Return the client public ID if found else null. If credentials have are needed to authenticate the client, they are set to the variable $client_credentials
     */
    public function findClientId(ServerRequestInterface $request, &$client_credentials = null);

    /**
     * @param array $command_parameters
     * @param array $validated_parameters
     *
     * @throws \InvalidArgumentException
     */
    public function checkClientConfiguration(array $command_parameters, array &$validated_parameters);

    /**
     * This method verifies the client credentials in the request.
     *
     * @param Client                                   $client
     * @param mixed                                    $client_credentials
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool Returns true if the client is authenticated, else false
     */
    public function isClientAuthenticated(Client $client, $client_credentials, ServerRequestInterface $request): bool;

    /**
     * @return array
     */
    public function getSchemesParameters(): array;
}
