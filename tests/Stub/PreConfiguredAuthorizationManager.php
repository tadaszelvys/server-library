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
     * PreConfiguredAuthorizationManager constructor.
     *
     * @param \OAuth2\Test\Stub\ClientManager $client_manager
     */
    public function __construct(ClientManager $client_manager)
    {
        foreach ($this->getPreConfiguredAuthorizations($client_manager) as $preConfiguredAuthorization) {
            $auth = $this->createPreConfiguredAuthorization();
            $auth->setClientPublicId($preConfiguredAuthorization['client_public_id']);
            $auth->setResourceOwnerPublicId($preConfiguredAuthorization['resource_owner_public_id']);
            $auth->setUserAccountPublicId($preConfiguredAuthorization['user_account_public_id']);
            $auth->setRequestedScopes($preConfiguredAuthorization['requested_scopes']);
            $auth->setValidatedScopes($preConfiguredAuthorization['validated_scopes']);
            $this->savePreConfiguredAuthorization($auth);
        }
    }

    /**
     * @param \OAuth2\Test\Stub\ClientManager $client_manager
     *
     * @return array
     */
    protected function getPreConfiguredAuthorizations(ClientManager $client_manager)
    {
        return [
            [
                'client_public_id'         => $client_manager->getClientByName('foo')->getPublicId(),
                'resource_owner_public_id' => 'real_user1_public_id',
                'user_account_public_id'   => 'user1',
                'requested_scopes'         => ['openid', 'email', 'profile'],
                'validated_scopes'         => ['openid', 'email', 'profile'],
            ],
            [
                'client_public_id'         => $client_manager->getClientByName('Mufasa')->getPublicId(),
                'resource_owner_public_id' => 'real_user1_public_id',
                'user_account_public_id'   => 'user1',
                'requested_scopes'         => ['openid', 'email', 'profile'],
                'validated_scopes'         => ['openid', 'email', 'profile'],
            ],
        ];
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
