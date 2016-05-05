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
use OAuth2\Client\Extension\TokenLifetimeExtensionInterface;
use OAuth2\User\UserInterface;

abstract class AuthCodeManager implements AuthCodeManagerInterface
{
    /**
     * @var \OAuth2\Token\TokenUpdaterInterface[]
     */
    private $token_updaters = [];

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
    public function createAuthCode(ClientInterface $client, UserInterface $resource_owner, array $query_params, $redirectUri, array $scope = [], $issueRefreshToken = false)
    {
        $auth_code = $this->createEmptyAuthorizationCode();
        $auth_code->setScope($scope);
        $auth_code->setResourceOwnerPublicId($resource_owner->getPublicId());
        $auth_code->setClientPublicId($client->getPublicId());
        $auth_code->setExpiresAt(time() + $this->getLifetime($client));
        $auth_code->setToken($this->generateAuthorizationCode());
        $auth_code->setIssueRefreshToken($issueRefreshToken);
        $auth_code->setQueryParams($query_params);
        $auth_code->setMetadata('redirect_uri', $redirectUri);

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

        return Base64Url::encode(random_bytes($length));
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
     * @param \OAuth2\Token\AuthCodeInterface $auth_code
     */
    private function updateAuthCode(AuthCodeInterface &$auth_code)
    {
        foreach ($this->token_updaters as $token_updater) {
            $token_updater->updateToken($auth_code);
        }
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
        Assertion::greaterThan($authorization_code_lifetime, 0);
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
        Assertion::greaterThan($authorization_code_min_length, 0);
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
