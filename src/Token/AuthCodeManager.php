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
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Security\DefuseGenerator;

abstract class AuthCodeManager implements AuthCodeManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * @var \OAuth2\Token\TokenUpdaterInterface[]
     */
    private $token_updaters = [];

    /**
     * AuthCodeManager constructor.
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
     * @param \OAuth2\Token\AuthCodeInterface $auth_code
     */
    abstract protected function saveAuthorizationCode(AuthCodeInterface $auth_code);

    /**
     * @return \OAuth2\Token\AuthCodeInterface
     */
    protected function createEmptyAuthorizationCode()
    {
        return new AuthCode();
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthCode(ClientInterface $client, EndUserInterface $resource_owner, array $query_params, $redirectUri, array $scope = [], $issueRefreshToken = false)
    {
        $auth_code = $this->createEmptyAuthorizationCode();
        $auth_code->setScope($scope);
        $auth_code->setResourceOwnerPublicId($resource_owner->getPublicId());
        $auth_code->setClientPublicId($client->getPublicId());
        $auth_code->setExpiresAt(time() + $this->getLifetime($client));
        $auth_code->setToken($this->generateAuthorizationCode());
        $auth_code->setIssueRefreshToken($issueRefreshToken);
        $auth_code->setQueryParams($query_params);
        $auth_code->setRedirectUri($redirectUri);

        $this->updateAuthCode($auth_code);
        $this->saveAuthorizationCode($auth_code);

        return $auth_code;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function generateAuthorizationCode()
    {
        $length = $this->getAuthCodeLength();
        $charset = $this->getConfiguration()->get('auth_code_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $code = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($code) || strlen($code) !== $length) {
            throw $this->createException('An error has occurred during the creation of the authorization code.');
        }

        return $code;
    }

    /**
     * {@inheritdoc}
     */
    private function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getConfiguration()->get('auth_code_lifetime', 30);
        if ($client instanceof TokenLifetimeExtensionInterface && ($_lifetime = $client->getTokenLifetime('authcode')) !== null) {
            return $_lifetime;
        }

        return $lifetime;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getAuthCodeLength()
    {
        $min_length = $this->getConfiguration()->get('auth_code_min_length', 20);
        $max_length = $this->getConfiguration()->get('auth_code_max_length', 30);
        srand();

        return rand(min($min_length, $max_length), max($min_length, $max_length));
    }

    /**
     * @param string $message
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    private function createException($message)
    {
        return $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, $message);
    }

    /**
     * @param \OAuth2\Token\AuthCodeInterface $auth_code
     */
    private function updateAuthCode(AuthCodeInterface &$auth_code)
    {
        foreach ($this->token_updaters as $token_updater) {
            $token_updater->updateToken($auth_code);
        }
    }
}
