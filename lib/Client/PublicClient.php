<?php

namespace OAuth2\Client;

/**
 * This interface is for registered clients.
 * These clients have an ID and the server can get the client details.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
class PublicClient extends RegisteredClient implements PublicClientInterface
{
    public function __construct()
    {
        parent::__construct();
        $this->setType('public_client');
    }
}
