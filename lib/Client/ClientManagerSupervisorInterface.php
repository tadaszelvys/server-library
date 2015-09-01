<?php

namespace OAuth2\Client;

use Symfony\Component\HttpFoundation\Request;

interface ClientManagerSupervisorInterface
{
    /**
     * Get a client using its Id.
     *
     * @param string $client_id The Id of the client
     *
     * @return null|\OAuth2\Client\ClientInterface Return the client object or null if no client is found.
     */
    public function getClient($client_id);

    /**
     * Find a client ID using the request
     * This interface should send the request to all its ClientManager and return null or a ClientInterface object.
     * If client is Confidential, the client credentials must be checked by by the client manager.
     *
     * @param Request     $request                The request
     * @param null|string $client_public_id_found If a public client ID is found in the request, but the authentication failed or client is not found, this value value is set
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface Throw an exception if a client tried to authenticate against the server, but failed
     *
     * @return \OAuth2\Client\ClientInterface Return the client object or null if no client is found.
     */
    public function findClient(Request $request, &$client_public_id_found = null);
}
