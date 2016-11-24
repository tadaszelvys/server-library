<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Assert\Assertion;
use OAuth2\Grant\ResponseTypeInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\ResponseMode\ResponseModeInterface;

class Authorization
{
    /**
     * @var bool
     */
    private $authorized;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var UserAccount
     */
    private $userAccount;

    /**
     * @var array
     */
    private $scopes = [];

    /**
     * @var array
     */
    private $data = [];

    /**
     * @var ResponseTypeInterface[]
     */
    private $responseTypes = [];

    /**
     * @var ResponseModeInterface
     */
    private $responseMode = null;

    /**
     * @var array
     */
    private $query_params = [];

    /**
     * @var string
     */
    private $redirect_uri;

    /**
     * Authorization constructor.
     *
     * @param array                                      $query_params
     * @param Client             $client
     * @param ResponseTypeInterface[]      $responseTypes
     * @param ResponseModeInterface $responseMode
     * @param string                                     $redirect_uri
     * @param string[]                                   $scopes
     */
    public function __construct(array $query_params, Client $client, array $responseTypes, ResponseModeInterface $responseMode, $redirect_uri, array $scopes)
    {
        Assertion::allIsInstanceOf($responseTypes, ResponseTypeInterface::class);
        $this->scopes = $scopes;
        $this->client = $client;
        $this->query_params = $query_params;
        $this->responseMode = $responseMode;
        $this->responseTypes = $responseTypes;
        $this->redirect_uri = $redirect_uri;
    }

    /**
     * @param UserAccount $userAccount
     * @return self
     */
    public function withUserAccount(UserAccount $userAccount): self
    {
        $clone = clone $this;
        $clone->userAccount = $userAccount;

        return $clone;
    }

    /**
     * @return UserAccount
     */
    public function getUserAccount(): UserAccount
    {
        return $this->userAccount;
    }

    /**
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }

    /**
     * @return array
     */
    public function getQueryParams(): array
    {
        return $this->query_params;
    }

    /**
     * @return string[]
     */
    public function getPrompt(): array
    {
        if (!$this->hasQueryParam('prompt')) {
            return [];
        }

        return $this->getQueryParam('prompt');
    }

    /**
     * @param string $prompt
     * @return bool
     */
    public function hasPrompt(string $prompt): bool
    {
        Assertion::string($prompt);

        return in_array($prompt, $this->getPrompt());
    }

    /**
     * @param array $scope
     * @return self
     */
    public function withScopes(array $scope): self
    {
        $clone = clone $this;
        $clone->scopes += $scope;

        return $this;
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @param string $scope
     * @return bool
     */
    public function hasScope(string $scope): bool
    {
        Assertion::string($scope);

        return null !== $this->scopes && in_array($scope, $this->scopes);
    }

    /**
     * @param string $scope
     * @return self
     */
    public function withoutScope(string $scope): self
    {
        if (!$this->hasScope($scope)) {
            return $this;
        }
        $clone = clone $this;
        unset($clone->scopes[array_search($scope, $clone->scopes)]);

        return $clone;
    }

    /**
     * @param string $scope
     * @return self
     */
    public function addScope(string $scope): self
    {
        if ($this->hasScope($scope)) {
            return $this;
        }
        $clone = clone $this;
        $clone->scopes[] = $scope;

        return $clone;
    }

    /**
     * @return bool
     */
    public function isAuthorized(): bool
    {
        return $this->authorized;
    }

    /**
     * @return self
     */
    public function allow(): self
    {
        $clone = clone $this;
        $clone->authorized = true;

        return $clone;
    }

    /**
     * @return self
     */
    public function deny(): self
    {
        $clone = clone $this;
        $clone->authorized = false;

        return $clone;
    }

    /**
     * @param string $param
     * @return bool
     */
    public function hasQueryParam(string $param): bool
    {
        Assertion::string($param);

        return array_key_exists($param, $this->query_params);
    }

    /**
     * @param string $param
     * @return mixed
     */
    public function getQueryParam(string $param)
    {
        Assertion::string($param);
        Assertion::true($this->hasQueryParam($param), sprintf('Invalid parameter "%s"', $param));

        return $this->query_params[$param];
    }

    /**
     * @param string $key
     * @return bool
     */
    public function hasData(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    /**
     * @param string $key
     * @return mixed
     */
    public function getData(string $key)
    {
        Assertion::true($this->hasData($key), sprintf('Invalid data "%s"', $key));

        return $this->data[$key];
    }

    /**
     * @param string $key
     * @param mixed $data
     * @return self
     */
    public function withData(string $key, $data): self
    {
        $clone = clone $this;
        $clone->data[$key] = $data;

        return $clone;
    }

    /**
     * @return ResponseTypeInterface[]
     */
    public function getResponseTypes(): array
    {
        return $this->responseTypes;
    }

    /**
     * @return string
     */
    public function getRedirectUri(): string
    {
        return $this->redirect_uri;
    }

    /**
     * @return ResponseModeInterface
     */
    public function getResponseMode(): ResponseModeInterface
    {
        return $this->responseMode;
    }
}
