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
interface ClientInterface extends ResourceOwnerInterface, \JsonSerializable
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
     * Checks if the response type is allowed for the client.
     *
     * @param string $response_type The response type
     *
     * @return bool true if the response type is allowed, else false
     */
    public function isResponseTypeAllowed($response_type);

    /**
     * Checks if the token type is allowed for the client.
     *
     * @param string $token_type The token type
     *
     * @return bool true if the token type is allowed, else false
     */
    public function isTokenTypeAllowed($token_type);

    /**
     * @return bool
     */
    public function isPublic();

    /**
     * @return bool
     */
    public function areClientCredentialsExpired();

    /**
     * @return bool
     */
    public function hasPublicKeySet();

    /**
     * @return null|\Jose\Object\JWKSetInterface
     */
    public function getPublicKeySet();

    /**
     * @param string $token Type of token (e.g. authcode, access_token, refresh_token or any other custom token type)
     *
     * @return null|int Returns null if no lifetime has been set for the token type, else an integer that repnesents the lifetime in seconds.
     */
    public function getTokenLifetime($token);
}
