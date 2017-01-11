<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\IdToken;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;

final class CreateIdTokenCommand extends CommandWithDataTransporter
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var UserAccount
     */
    private $userAccount;

    /**
     * @var string
     */
    private $redirectUri;

    /**
     * @var array
     */
    private $requestClaims;

    /**
     * @var array
     */
    private $claimsLocales;

    /**
     * @var array
     */
    private $scopes;

    /**
     * @var array
     */
    private $idTokenClaims;

    /**
     * @var null|AccessToken
     */
    private $accessToken = null;

    /**
     * @var null|AuthCode
     */
    private $authCode = null;

    /**
     * CreateIdTokenCommand constructor.
     * @param Client $client
     * @param UserAccount $userAccount
     * @param string $redirectUri
     * @param array $requestClaims
     * @param array $claimsLocales
     * @param array $scopes
     * @param array $idTokenClaims
     * @param AccessToken|null $accessToken
     * @param AuthCode|null $authCode
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(Client $client, UserAccount $userAccount, string $redirectUri, array $requestClaims, array $claimsLocales, array $scopes, array $idTokenClaims, AccessToken $accessToken = null, AuthCode $authCode = null, DataTransporter $dataTransporter = null)
    {
        $this->client = $client;
        $this->userAccount = $userAccount;
        $this->redirectUri = $redirectUri;
        $this->requestClaims = $requestClaims;
        $this->claimsLocales = $claimsLocales;
        $this->scopes = $scopes;
        $this->idTokenClaims = $idTokenClaims;
        $this->accessToken = $accessToken;
        $this->authCode = $authCode;
        parent::__construct($dataTransporter);
    }

    /**
     * @param Client $client
     * @param UserAccount $userAccount
     * @param string $redirectUri
     * @param array $requestClaims
     * @param array $claimsLocales
     * @param array $scopes
     * @param array $idTokenClaims
     * @param AccessToken|null $accessToken
     * @param AuthCode|null $authCode
     * @param DataTransporter|null $dataTransporter
     * @return CreateIdTokenCommand
     */
    public static function create(Client $client, UserAccount $userAccount, string $redirectUri, array $requestClaims, array $claimsLocales, array $scopes, array $idTokenClaims, AccessToken $accessToken = null, AuthCode $authCode = null, DataTransporter $dataTransporter = null): self
    {
        return new self($client, $userAccount, $redirectUri, $requestClaims, $claimsLocales, $scopes, $idTokenClaims, $accessToken, $authCode, $dataTransporter);
    }

    /**
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }

    /**
     * @return UserAccount
     */
    public function getUserAccount(): UserAccount
    {
        return $this->userAccount;
    }

    /**
     * @return string
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    /**
     * @return array
     */
    public function getRequestClaims(): array
    {
        return $this->requestClaims;
    }

    /**
     * @return array
     */
    public function getClaimsLocales(): array
    {
        return $this->claimsLocales;
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return array
     */
    public function getIdTokenClaims(): array
    {
        return $this->idTokenClaims;
    }

    /**
     * @return null|AccessToken
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * @return null|AuthCode
     */
    public function getAuthCode()
    {
        return $this->authCode;
    }
}
