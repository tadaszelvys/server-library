<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
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
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return null|string|\OAuth2\Client\ClientInterface Return the client if found else null. If a client tried to authenticate against the server but failed, return the public ID found
     */
    public function findClient(ServerRequestInterface $request);

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
