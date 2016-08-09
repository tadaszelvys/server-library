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
     * @return \OAuth2\Client\ClientInterface Return a new client object.
     */
    public function createClient();

    /**
     * Get a client using its Id.
     *
     * @param string $client_id The Id of the client
     *
     * @return null|\OAuth2\Client\ClientInterface Return the client object or null if no client is found.
     */
    public function getClient($client_id);

    /**
     * Save the client
     *
     * @param \OAuth2\Client\ClientInterface $client
     */
    public function saveClient(ClientInterface $client);

    /**
     * Find a client ID using the request
     * This interface should send the request to all its ClientManager and return null or a ClientInterface object.
     * If client is Confidential, the client credentials must be checked by by the client manager.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface Throw an exception if a client tried to authenticate against the server, but failed
     *
     * @return \OAuth2\Client\ClientInterface Return the client object.
     */
    public function findClient(ServerRequestInterface $request);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    public function buildAuthenticationException(ServerRequestInterface $request);
}
