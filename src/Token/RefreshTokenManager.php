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

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use Security\DefuseGenerator;

abstract class RefreshTokenManager implements RefreshTokenManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * @var \OAuth2\Token\TokenUpdaterInterface[]
     */
    private $token_updaters = [];

    /**
     * ClientCredentialsGrantType constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

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
        $charset = $this->getConfiguration()->get('refresh_token_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $token = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($token) || strlen($token) !== $length) {
            throw $this->createException('An error has occurred during the creation of the refresh token.');
        }

        return $token;
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

        return  $this->getConfiguration()->get('refresh_token_lifetime', 1209600);
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getRefreshTokenLength()
    {
        $min_length = $this->getConfiguration()->get('refresh_token_min_length', 20);
        $max_length = $this->getConfiguration()->get('refresh_token_max_length', 30);
        srand();

        return rand(min($min_length, $max_length), max($min_length, $max_length));
    }

    /**
     * @param $message
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    private function createException($message)
    {
        return $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, $message);
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
}
