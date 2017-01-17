<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\PreConfiguredAuthorization;

interface PreConfiguredAuthorizationManagerInterface
{
    /**
     * @param string   $resource_owner_public_id
     * @param string   $client_public_id
     * @param string[] $request_scope
     *
     * @return \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface|null
     */
    public function findOnePreConfiguredAuthorization($resource_owner_public_id, $client_public_id, array $request_scope);

    /**
     * @return \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface
     */
    public function createPreConfiguredAuthorization();

    /**
     * @param \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface $pre_configured_authorization
     */
    public function savePreConfiguredAuthorization(PreConfiguredAuthorizationInterface $pre_configured_authorization);
}
