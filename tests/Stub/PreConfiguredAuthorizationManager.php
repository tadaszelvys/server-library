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

namespace OAuth2\Test\Stub;

use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorization;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationRepositoryInterface;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;

class PreConfiguredAuthorizationRepository implements PreConfiguredAuthorizationRepositoryInterface
{
    /**
     * @var PreConfiguredAuthorization[]
     */
    private $preConfiguredAuthorizations = [];

    /**
     * PreConfiguredAuthorizationManager constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     */
    public function __construct(ClientRepositoryInterface $clientRepository)
    {
        foreach ($this->getPreConfiguredAuthorizations($clientRepository) as $preConfiguredAuthorization) {
            $auth = $this->createPreConfiguredAuthorization();
            $auth->setClientPublicId($preConfiguredAuthorization['client_public_id']);
            $auth->setResourceOwnerPublicId($preConfiguredAuthorization['resource_owner_public_id']);
            $auth->setUserAccountPublicId($preConfiguredAuthorization['user_account_public_id']);
            $auth->setScopes($preConfiguredAuthorization['scopes']);
            $this->savePreConfiguredAuthorization($auth);
        }
    }

    /**
     * @param ClientRepositoryInterface $clientRepository
     *
     * @return array
     */
    protected function getPreConfiguredAuthorizations(ClientRepositoryInterface $clientRepository)
    {
        return [
            [
                'client_public_id'         => $clientRepository->find(ClientId::create('foo'))->getId()->getValue(),
                'resource_owner_public_id' => 'real_user1_public_id',
                'user_account_public_id'   => 'user1',
                'scopes'                   => ['openid', 'email', 'profile'],
                'validated_scopes'         => ['openid', 'email', 'profile'],
            ],
            [
                'client_public_id'         => $clientRepository->find(ClientId::create('Mufasa'))->getId()->getValue(),
                'resource_owner_public_id' => 'real_user1_public_id',
                'user_account_public_id'   => 'user1',
                'scopes'                   => ['openid', 'email', 'profile'],
                'validated_scopes'         => ['openid', 'email', 'profile'],
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function findOne(ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $scope)
    {
        $hash = $this->calculateHash($resourceOwnerId, $clientId, $scope);
        if (array_key_exists($hash, $this->preConfiguredAuthorizations)) {
            return $this->preConfiguredAuthorizations[$hash];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function create(): PreConfiguredAuthorization
    {
        return new PreConfiguredAuthorization();
    }

    /**
     * {@inheritdoc}
     */
    public function save(PreConfiguredAuthorization $preConfiguredAuthorization): PreConfiguredAuthorizationRepositoryInterface
    {
        $hash = $this->calculateHash(
            $preConfiguredAuthorization->getResourceOwnerId(),
            $preConfiguredAuthorization->getClientId(),
            $preConfiguredAuthorization->getScopes()
        );
        $this->preConfiguredAuthorizations[$hash] = $preConfiguredAuthorization;

        return $this;
    }

    /**
     * @param ResourceOwnerId $resourceOwnerId
     * @param ClientId        $clientId
     * @param \string[]       $scope
     *
     * @return string
     */
    private function calculateHash(ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $scope)
    {
        return hash(
            'sha512',
            sprintf(
                '%s%s%s',
                $resourceOwnerId,
                $clientId,
                implode(' ', $scope)
            )
        );
    }
}
