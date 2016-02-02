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
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Security\DefuseGenerator;

abstract class AuthCodeManager implements AuthCodeManagerInterface
{
    use HasExceptionManager;

    /**
     * @var \OAuth2\Token\TokenUpdaterInterface[]
     */
    private $token_updaters = [];

    /**
     * @var string
     */
    private $authorization_code_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/';

    /**
     * @var int
     */
    private $authorization_code_lifetime = 30;

    /**
     * @var int
     */
    private $authorization_code_min_length = 20;

    /**
     * @var int
     */
    private $authorization_code_max_length = 50;

    /**
     * AuthCodeManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
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
        $charset = $this->getAuthorizationCodeCharset();
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
        $lifetime = $this->getAuthorizationCodeLifetime();
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
        $min_length = $this->getAuthorizationCodeMinLength();
        $max_length = $this->getAuthorizationCodeMaxLength();
        srand();

        return rand($min_length, $max_length);
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

    /**
     * @return string
     */
    public function getAuthorizationCodeCharset()
    {
        return $this->authorization_code_charset;
    }

    /**
     * @param string $authorization_code_charset
     */
    public function setAuthorizationCodeCharset($authorization_code_charset)
    {
        Assertion::string($authorization_code_charset);
        $this->authorization_code_charset = $authorization_code_charset;
    }

    /**
     * @return int
     */
    public function getAuthorizationCodeLifetime()
    {
        return $this->authorization_code_lifetime;
    }

    /**
     * @param int $authorization_code_lifetime
     */
    public function setAuthorizationCodeLifetime($authorization_code_lifetime)
    {
        Assertion::integer($authorization_code_lifetime);
        $this->authorization_code_lifetime = $authorization_code_lifetime;
    }

    /**
     * @return int
     */
    public function getAuthorizationCodeMinLength()
    {
        return $this->authorization_code_min_length;
    }

    /**
     * @param int $authorization_code_min_length
     */
    public function setAuthorizationCodeMinLength($authorization_code_min_length)
    {
        Assertion::integer($authorization_code_min_length);
        Assertion::lessThan($authorization_code_min_length, $this->getAuthorizationCodeMaxLength());
        $this->authorization_code_min_length = $authorization_code_min_length;
    }

    /**
     * @return int
     */
    public function getAuthorizationCodeMaxLength()
    {
        return $this->authorization_code_max_length;
    }

    /**
     * @param int $authorization_code_max_length
     */
    public function setAuthorizationCodeMaxLength($authorization_code_max_length)
    {
        Assertion::integer($authorization_code_max_length);
        Assertion::greaterThan($authorization_code_max_length, $this->getAuthorizationCodeMinLength());
        $this->authorization_code_max_length = $authorization_code_max_length;
    }
}
