<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\Extension\TokenLifetimeExtensionInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

abstract class AccessTokenManager implements AccessTokenManagerInterface
{
    /**
     * @var \OAuth2\Token\TokenUpdaterInterface[]
     */
    private $token_updaters = [];

    /**
     * @var int
     */
    private $access_token_lifetime = 3600;

    /**
     * {@inheritdoc}
     */
    public function addTokenUpdater(TokenUpdaterInterface $token_updater)
    {
        $this->token_updaters[] = $token_updater;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface           $access_token
     * @param \OAuth2\Client\ClientInterface               $client
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resource_owner
     * @param \OAuth2\Token\RefreshTokenInterface|null     $refresh_token
     * @param \OAuth2\Client\ClientInterface|null          $resource_server
     */
    abstract protected function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null, ClientInterface $resource_server = null);

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     */
    abstract protected function saveAccessToken(AccessTokenInterface $access_token);

    /**
     * @return \OAuth2\Token\AccessTokenInterface
     */
    protected function createEmptyAccessToken()
    {
        return new AccessToken();
    }

    /**
     * {@inheritdoc}
     */
    public function createAccessToken(ClientInterface $client, ResourceOwnerInterface $resource_owner, array $token_type_parameters, array $request_parameters, array $scope = [], RefreshTokenInterface $refresh_token = null, ClientInterface $resource_server = null, array $metadatas = [])
    {
        $access_token = $this->createEmptyAccessToken();
        $access_token->setExpiresAt(time() + $this->getLifetime($client));
        $access_token->setScope($scope);
        $access_token->setResourceOwnerPublicId($resource_owner->getPublicId());
        $access_token->setClientPublicId($client->getPublicId());
        $access_token->setRefreshToken(null === $refresh_token ? null : $refresh_token->getToken());
        $access_token->setMetadatas($metadatas);

        foreach ($token_type_parameters as $key => $value) {
            if ('token_type' === $key) {
                $access_token->setTokenType($value);
            } else {
                $access_token->setParameter($key, $value);
            }
        }

        $this->updateAccessToken($access_token);
        $this->populateAccessToken($access_token, $client, $resource_owner, $refresh_token, $resource_server);
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
        $lifetime = $this->getAccessTokenLifetime();
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

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     */
    private function updateAccessToken(AccessTokenInterface &$access_token)
    {
        foreach ($this->token_updaters as $token_updater) {
            $token_updater->updateToken($access_token);
        }
    }

    /**
     * @return int
     */
    public function getAccessTokenLifetime()
    {
        return $this->access_token_lifetime;
    }

    /**
     * @param int $access_token_lifetime
     */
    public function setAccessTokenLifetime($access_token_lifetime)
    {
        Assertion::integer($access_token_lifetime);
        Assertion::greaterThan($access_token_lifetime, 0);
        $this->access_token_lifetime = $access_token_lifetime;
    }
}
