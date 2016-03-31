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

use OAuth2\ResourceOwner\ResourceOwnerInterface;

/**
 * Interface ClientInterface.
 *
 * This interface is used for every client types.
 * A client is a resource owner with a set of allowed grant types and can perform requests against
 * available endpoints.
 */
interface ClientInterface extends ResourceOwnerInterface
{
    /**
     * Checks if the grant type is allowed for the client.
     *
     * @param string $grant_type The grant type
     *
     * @return bool true if the grant type is allowed, else false
     */
    public function isGrantTypeAllowed($grant_type);

    /**
     * @return string[]
     */
    public function getAllowedGrantTypes();

    /**
     * Checks if the token type is allowed for the client.
     *
     * @param string $token_type The token type
     *
     * @return bool true if the token type is allowed, else false
     */
    public function isTokenTypeAllowed($token_type);

    /**
     * @return string[]
     */
    public function getAllowedTokenTypes();

    /**
     * Checks if the response type is allowed for the client.
     *
     * @param string $response_type The response type
     *
     * @return bool true if the response type is allowed, else false
     */
    public function isResponseTypeAllowed($response_type);

    /**
     * @return string[]
     */
    public function getAllowedResponseTypes();
}
