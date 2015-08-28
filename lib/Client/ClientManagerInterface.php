<?php

namespace OAuth2\Client;

use Symfony\Component\HttpFoundation\Request;

interface ClientManagerInterface
{
    /**
     * Find a client using the request.
     * If the client is confidential, the client credentials must be checked.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request                The request
     * @param null|string                               $client_public_id_found If a public client ID is found in the request, but the authentication failed or client is not found, this value value is set
     *
     * @return null|string|\OAuth2\Client\ClientInterface Return the client if found else null. If a client tried to authenticate against the server but failed, return the public ID found
     */
    public function findClient(Request $request, &$client_public_id_found = null);

    /**
     * Get a client by its ID.
     *
     * @param string $client_id The client ID
     *
     * @return null|\OAuth2\Client\ClientInterface Return the client object or null if no client has been found.
     */
    public function getClient($client_id);
}
