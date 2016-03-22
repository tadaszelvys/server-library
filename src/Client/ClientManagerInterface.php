<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use Psr\Http\Message\ServerRequestInterface;

interface ClientManagerInterface
{
    /**
     * Find a client using the request.
     * If the client is confidential, the client credentials must be checked.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request            The request
     * @param mixed                                    $client_credentials The client credentials found in the request
     *
     * @return null|\OAuth2\Client\ClientInterface Return the client if found else null.
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null);

    /**
     * This method verifies the client credentials in the request.
     *
     * @param \OAuth2\Client\ClientInterface           $client
     * @param mixed                                    $client_credentials
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool Returns true if the client is authenticated, else false
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request);

    /**
     * Get a client by its ID.
     *
     * @param string $client_id The client ID
     *
     * @return null|\OAuth2\Client\ClientInterface Return the client object or null if no client has been found.
     */
    public function getClient($client_id);

    /**
     * @return array
     */
    public function getSchemesParameters();
}
