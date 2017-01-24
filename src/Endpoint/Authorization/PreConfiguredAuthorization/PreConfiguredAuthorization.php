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
use OAuth2\Model\UserAccount\UserAccountId;

final class PreConfiguredAuthorization
{
    /**
     * @var ResourceOwnerId
     */
    private $resourceOwnerId;

    /**
     * @var UserAccountId
     */
    private $userAccountId;

    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var string[]
     */
    private $scopes;

    /**
     * @return ResourceOwnerId
     */
    public function getResourceOwnerId(): ResourceOwnerId
    {
        return $this->resourceOwnerId;
    }

    /**
     * @param ResourceOwnerId $resourceOwnerId
     */
    public function setResourceOwnerId(ResourceOwnerId $resourceOwnerId)
    {
        $this->resourceOwnerId = $resourceOwnerId;
    }

    /**
     * @return UserAccountId
     */
    public function getUserAccountId(): UserAccountId
    {
        return $this->userAccountId;
    }

    /**
     * @param UserAccountId $userAccountId
     */
    public function setUserAccountId(UserAccountId $userAccountId)
    {
        $this->userAccountId = $userAccountId;
    }

    /**
     * @return ClientId
     */
    public function getClientId(): ClientId
    {
        return $this->clientId;
    }

    /**
     * @param ClientId $clientId
     */
    public function setClientId(ClientId $clientId)
    {
        $this->clientId = $clientId;
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @param array $scopes
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
    }
}
