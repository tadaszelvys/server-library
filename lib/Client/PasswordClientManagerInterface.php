<?php

namespace OAuth2\Client;

interface PasswordClientManagerInterface extends ClientManagerInterface
{
    /**
     * Tries to find a client using the A1 part of the digest authentication scheme.
     *
     * @param string $a1
     *
     * @return null|\OAuth2\Client\ClientInterface Return the client object or null if no client has been found.
     */
    public function getClientFromA1($a1);
}
