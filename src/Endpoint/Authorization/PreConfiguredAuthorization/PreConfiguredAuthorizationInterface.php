<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\PreConfiguredAuthorization;

interface PreConfiguredAuthorizationInterface
{
    /**
     * @return string
     */
    public function getResourceOwnerPublicId();

    /**
     * @param string $resource_owner_public_id
     */
    public function setResourceOwnerPublicId($resource_owner_public_id);

    /**
     * @return string
     */
    public function getUserAccountPublicId();

    /**
     * @param string $user_account_public_id
     */
    public function setUserAccountPublicId($user_account_public_id);

    /**
     * @return string
     */
    public function getClientPublicId();

    /**
     * @param string $client_public_id
     */
    public function setClientPublicId($client_public_id);

    /**
     * @return string[]
     */
    public function getScopes();

    /**
     * @param string[] $scopes
     */
    public function setScopes(array $scopes);
}
