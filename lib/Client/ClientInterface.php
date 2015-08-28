<?php

namespace OAuth2\Client;

use OAuth2\ResourceOwner\ResourceOwnerInterface;

interface ClientInterface extends ResourceOwnerInterface
{
    /**
     * Checks if the grant type is allowed for the client.
     *
     * @param string $grant_type The grant type
     *
     * @return bool true if the grant type is allowed, else false
     */
    public function isAllowedGrantType($grant_type);
}
