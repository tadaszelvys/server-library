<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorization;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface;

class PreConfiguredAuthorizationManager implements PreConfiguredAuthorizationManagerInterface
{
    /**
     * @var \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface[]
     */
    private $pre_configured_authorizations = [];

    /**
     * AuthCodeManager constructor.
     */
    public function __construct()
    {
        $auth1 = $this->createPreConfiguredAuthorization();
        $auth1->setClientPublicId('foo');
        $auth1->setResourceOwnerPublicId('user1');
        $auth1->setRequestedScopes(['openid', 'email', 'profile']);
        $auth1->setValidatedScopes(['openid', 'email', 'profile']);
        $this->savePreConfiguredAuthorization($auth1);
    }

    /**
     * {@inheritdoc}
     */
    public function findOnePreConfiguredAuthorization($resource_owner_public_id, $client_public_id, array $requested_scope)
    {
        $hash = $this->calculateHash($resource_owner_public_id, $client_public_id, $requested_scope);

        if (array_key_exists($hash, $this->pre_configured_authorizations)) {
            return $this->pre_configured_authorizations[$hash];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function createPreConfiguredAuthorization()
    {
        return new PreConfiguredAuthorization();
    }

    /**
     * {@inheritdoc}
     */
    public function savePreConfiguredAuthorization(PreConfiguredAuthorizationInterface $pre_configured_authorization)
    {
        $hash = $this->calculateHash(
            $pre_configured_authorization->getResourceOwnerPublicId(),
            $pre_configured_authorization->getClientPublicId(),
            $pre_configured_authorization->getRequestedScopes()
        );

        $this->pre_configured_authorizations[$hash] = $pre_configured_authorization;
    }

    /**
     * @param string   $resource_owner_public_id
     * @param string   $client_public_id
     * @param string[] $requested_scope
     *
     * @return string
     */
    private function calculateHash($resource_owner_public_id, $client_public_id, array $requested_scope)
    {
        return hash(
            'sha512',
            sprintf(
                '%s%s%s',
                $resource_owner_public_id,
                $client_public_id,
                implode(' ', $requested_scope)
            )
        );
    }
}
