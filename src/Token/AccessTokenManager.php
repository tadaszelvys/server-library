<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Behaviour\HasAccessTokenTypeManager;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

abstract class AccessTokenManager implements AccessTokenManagerInterface
{
    use HasConfiguration;
    use HasAccessTokenTypeManager;

    /**
     * AccessTokenManager constructor.
     *
     * @param \OAuth2\Configuration\ConfigurationInterface  $configuration
     * @param \OAuth2\Token\AccessTokenTypeManagerInterface $access_token_type_manager
     */
    public function __construct(ConfigurationInterface $configuration, AccessTokenTypeManagerInterface $access_token_type_manager)
    {
        $this->setConfiguration($configuration);
        $this->setAccessTokenTypeManager($access_token_type_manager);
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface           $access_token
     * @param \OAuth2\Client\ClientInterface               $client
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resource_owner
     * @param \OAuth2\Token\RefreshTokenInterface|null     $refresh_token
     */
    abstract protected function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null);

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     */
    abstract protected function saveAccessToken(AccessTokenInterface $access_token);

    /**
     * @return \OAuth2\Token\AccessTokenInterface
     */
    abstract protected function getClass();

    /**
     * {@inheritdoc}
     */
    public function createAccessToken(ClientInterface $client, ResourceOwnerInterface $resource_owner, array $scope = [], RefreshTokenInterface $refresh_token = null)
    {
        $access_token = $this->getClass();
        $access_token->setExpiresAt(time() + $this->getLifetime($client));
        $access_token->setScope($scope);
        $access_token->setResourceOwnerPublicId($resource_owner->getPublicId());
        $access_token->setClientPublicId($client->getPublicId());
        $access_token->setRefreshToken(null === $refresh_token ? null : $refresh_token->getToken());

        $this->populateAccessToken($access_token, $client, $resource_owner, $refresh_token);
        $token_type = $this->getAccessTokenTypeManager()->getAccessTokenTypeForClient($client);
        $token_type->updateAccessToken($access_token);
        $this->saveAccessToken($access_token);

        return $access_token;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    protected function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getConfiguration()->get('access_token_lifetime', 3600);
        if ($client instanceof TokenLifetimeExtensionInterface && is_int($_lifetime = $client->getTokenLifetime('access_token'))) {
            return $_lifetime;
        }

        return $lifetime;
    }

    /**
     * We only check if the token has not expired.
     * This method should be overridden to verify the client or the resource owner are enabled for example.
     *
     * {@inheritdoc}
     */
    public function isAccessTokenValid(AccessTokenInterface $token)
    {
        return !$token->hasExpired();
    }
}
