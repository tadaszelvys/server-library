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

use OAuth2\Model\Client\ClientId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;

interface PreConfiguredAuthorizationRepositoryInterface
{
    /**
     * @param ResourceOwnerId $resourceOwnerId
     * @param ClientId        $clientPublicId
     * @param \string[]       $request_scope
     *
     * @return PreConfiguredAuthorization|null
     */
    public function findOne(ResourceOwnerId $resourceOwnerId, ClientId $clientPublicId, array $request_scope);

    /**
     * @return PreConfiguredAuthorization
     */
    public function create(): PreConfiguredAuthorization;

    /**
     * @param PreConfiguredAuthorization $preConfiguredAuthorization
     *
     * @return PreConfiguredAuthorizationRepositoryInterface
     */
    public function save(PreConfiguredAuthorization $preConfiguredAuthorization): PreConfiguredAuthorizationRepositoryInterface;
}
