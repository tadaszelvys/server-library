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
use Base64Url\Base64Url;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

abstract class RefreshTokenManager implements RefreshTokenManagerInterface
{
    /**
     * @var \OAuth2\Token\TokenUpdaterInterface[]
     */
    private $token_updaters = [];

    /**
     * @var int
     */
    private $refresh_token_lifetime = 1209600;

    /**
     * @var int
     */
    private $refresh_token_min_length = 20;

    /**
     * @var int
     */
    private $refresh_token_max_length = 50;

    /**
     * {@inheritdoc}
     */
    public function addTokenUpdater(TokenUpdaterInterface $token_updater)
    {
        $this->token_updaters[] = $token_updater;
    }

    /**
     * @param \OAuth2\Token\RefreshTokenInterface $refresh_token
     */
    abstract protected function saveRefreshToken(RefreshTokenInterface $refresh_token);

    /**
     * @return \OAuth2\Token\RefreshTokenInterface
     */
    protected function createEmptyRefreshToken()
    {
        return new RefreshToken();
    }

    /**
     * {@inheritdoc}
     */
    public function createRefreshToken(ClientInterface $client, ResourceOwnerInterface $resource_owner, array $scope = [])
    {
        $refresh_token = $this->createEmptyRefreshToken();
        $refresh_token->setScope($scope);
        $refresh_token->setResourceOwnerPublicId($resource_owner->getPublicId());
        $refresh_token->setClientPublicId($client->getPublicId());
        $refresh_token->setExpiresAt(time() + $this->getLifetime($client));
        $refresh_token->setUsed(false);
        $refresh_token->setToken($this->generateToken());

        $this->updateRefreshToken($refresh_token);
        $this->saveRefreshToken($refresh_token);

        return $refresh_token;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function generateToken()
    {
        $length = $this->getRefreshTokenLength();

        return Base64Url::encode(random_bytes($length));
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    private function getLifetime(ClientInterface $client)
    {
        if ($client instanceof TokenLifetimeExtensionInterface && ($lifetime = $client->getTokenLifetime('refresh_token')) !== null) {
            return $lifetime;
        }

        return  $this->getRefreshTokenLifetime();
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getRefreshTokenLength()
    {
        $min_length = $this->getRefreshTokenMinLength();
        $max_length = $this->getRefreshTokenMaxLength();
        srand();

        return rand($min_length, $max_length);
    }

    /**
     * @param \OAuth2\Token\RefreshTokenInterface $refresh_token
     */
    private function updateRefreshToken(RefreshTokenInterface &$refresh_token)
    {
        foreach ($this->token_updaters as $token_updater) {
            $token_updater->updateToken($refresh_token);
        }
    }

    /**
     * @return int
     */
    public function getRefreshTokenLifetime()
    {
        return $this->refresh_token_lifetime;
    }

    /**
     * @param int $refresh_token_lifetime
     */
    public function setRefreshTokenLifetime($refresh_token_lifetime)
    {
        Assertion::integer($refresh_token_lifetime);
        Assertion::greaterThan($refresh_token_lifetime, 0);
        $this->refresh_token_lifetime = $refresh_token_lifetime;
    }

    /**
     * @return int
     */
    public function getRefreshTokenMinLength()
    {
        return $this->refresh_token_min_length;
    }

    /**
     * @param int $refresh_token_min_length
     */
    public function setRefreshTokenMinLength($refresh_token_min_length)
    {
        Assertion::integer($refresh_token_min_length);
        Assertion::greaterThan($refresh_token_min_length, 0);
        Assertion::lessThan($refresh_token_min_length, $this->getRefreshTokenMaxLength());
        $this->refresh_token_min_length = $refresh_token_min_length;
    }

    /**
     * @return int
     */
    public function getRefreshTokenMaxLength()
    {
        return $this->refresh_token_max_length;
    }

    /**
     * @param int $refresh_token_max_length
     */
    public function setRefreshTokenMaxLength($refresh_token_max_length)
    {
        Assertion::integer($refresh_token_max_length);
        Assertion::greaterThan($refresh_token_max_length, $this->getRefreshTokenMinLength());
        $this->refresh_token_max_length = $refresh_token_max_length;
    }
}
