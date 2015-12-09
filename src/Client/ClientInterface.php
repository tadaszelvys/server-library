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

    /**
     * @return string[]
     */
    public function getAllowedGrantTypes();

    /**
     * @param string[] $grant_types
     *
     * @return self
     */
    public function setAllowedGrantTypes(array $grant_types);

    /**
     * @param $grant_type
     *
     * @return self
     */
    public function addAllowedGrantType($grant_type);

    /**
     * @param string $grant_type
     *
     * @return self
     */
    public function removeAllowedGrantType($grant_type);
}
