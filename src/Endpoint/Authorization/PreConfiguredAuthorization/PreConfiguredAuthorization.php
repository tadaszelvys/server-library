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

class PreConfiguredAuthorization implements PreConfiguredAuthorizationInterface
{
    /**
     * @var string
     */
    private $resource_owner_public_id;

    /**
     * @var string
     */
    private $user_account_public_id;

    /**
     * @var string
     */
    private $client_public_id;

    /**
     * @var string[]
     */
    private $scopes;

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerPublicId()
    {
        return $this->resource_owner_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setResourceOwnerPublicId($resource_owner_public_id)
    {
        $this->resource_owner_public_id = $resource_owner_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserAccountPublicId()
    {
        return $this->user_account_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setUserAccountPublicId($user_account_public_id)
    {
        $this->user_account_public_id = $user_account_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientPublicId()
    {
        return $this->client_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setClientPublicId($client_public_id)
    {
        $this->client_public_id = $client_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
    }
}
