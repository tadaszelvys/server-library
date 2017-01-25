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

namespace OAuth2\Model\Scope;

use Assert\Assertion;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManager;

class ScopeRepository
{
    /**
     * @var string[]
     */
    private $availableScopes = [];

    /**
     * @var ScopePolicyInterface[]
     */
    private $scopePolicies = [];

    /**
     * @var string
     */
    private $defaultScopePolicy;

    /**
     * @var OAuth2ResponseFactoryManager
     */
    private $responseFactoryManager;

    /**
     * ScopeManager constructor.
     *
     * @param OAuth2ResponseFactoryManager $responseFactoryManager
     * @param array                                 $availableScopes
     */
    public function __construct(OAuth2ResponseFactoryManager $responseFactoryManager, array $availableScopes = [])
    {
        $this->availableScopes = $availableScopes;
        $this->responseFactoryManager = $responseFactoryManager;
        $this->addScopePolicy(new NoScopePolicy(), true);
    }

    /**
     * @param ScopePolicyInterface $scopePolicy
     * @param bool                 $isDefault
     *
     * @return ScopeRepository
     */
    public function addScopePolicy(ScopePolicyInterface $scopePolicy, bool $isDefault = false): ScopeRepository
    {
        $name = $scopePolicy->name();
        $this->scopePolicies[$name] = $scopePolicy;

        if (true === $isDefault) {
            $this->defaultScopePolicy = $name;
        }

        return $this;
    }

    /**
     * @return string[]
     */
    public function getSupportedScopePolicies(): array
    {
        return array_keys($this->scopePolicies);
    }

    /**
     * This function returns the scope policy. If a valid Client object is set as parameter, the function will return scope policy for the client.
     *
     * @param string $scopePolicyName Scope policy
     *
     * @throws \InvalidArgumentException
     *
     * @return ScopePolicyInterface
     */
    public function getScopePolicy(string $scopePolicyName): ScopePolicyInterface
    {
        Assertion::keyExists($this->scopePolicies, $scopePolicyName, sprintf('The scope policy with name \'%s\' is not supported', $scopePolicyName));

        return $this->scopePolicies[$scopePolicyName];
    }

    /**
     * @return string[]
     */
    public function getSupportedScopes(): array
    {
        return $this->availableScopes;
    }

    /**
     * @return ScopePolicyInterface
     */
    public function getDefaultScopePolicy(): ScopePolicyInterface
    {
        return $this->scopePolicies[$this->defaultScopePolicy];
    }

    /**
     * This function returns the available scopes. If a valid Client object is set as parameter, the function will return available scopes for the client.
     *
     * @param Client $client A client
     *
     * @return string[] Return an array scope
     */
    public function getAvailableScopesForClient(Client $client): array
    {
        return ($client->has('scope')) ? $this->convertToArray($client->get('scope')) : $this->getSupportedScopes();
    }

    /**
     * This function returns the scope policy. If a valid Client object is set as parameter, the function will return scope policy for the client.
     *
     * @param Client $client A client
     *
     * @return ScopePolicyInterface
     */
    public function getScopePolicyForClient(Client $client): ScopePolicyInterface
    {
        if ($client->has('scope_policy') && null !== $policyName = $client->get('scope_policy')) {
            return $this->getScopePolicy($policyName);
        }

        return $this->getDefaultScopePolicy();
    }

    /**
     * This function check if the scopes respect the scope policy for the client.
     *
     * @param string[] $scope  The scopes
     * @param Client   $client A client
     *
     * @return string[] An array scopes according to the scope policy
     */
    public function checkScopePolicy(array $scope, Client $client): array
    {
        if (empty($scope)) {
            $policy = $this->getScopePolicyForClient($client);
            $policy->checkScopePolicy($scope, $client);
        }

        return $scope;
    }

    /**
     * @param string[] $requestedScopes An array of scopes that represents requested scopes
     * @param string[] $availableScopes An array of scopes that represents available scopes
     *
     * @return bool Return true if the requested scope is within the available scope
     */
    public function areRequestScopesAvailable(array $requestedScopes, array $availableScopes): bool
    {
        return 0 === count(array_diff($requestedScopes, $availableScopes));
    }

    /**
     * Convert a string that contains at least one scope to an array of scopes.
     *
     * @param string $scopes The string to convert
     *
     * @return string[] An array of scopes
     */
    public function convertToArray(string $scopes): array
    {
        $this->checkScopeCharset($scopes);
        $scopes = explode(' ', $scopes);

        foreach ($scopes as $scope) {
            $this->checkScopeUsedOnce($scope, $scopes);
        }

        return $scopes;
    }

    /**
     * @param string $scope
     * @param array  $scopes
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkScopeUsedOnce(string $scope, array $scopes)
    {
        if (1 < count(array_keys($scopes, $scope))) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManager::ERROR_INVALID_SCOPE,
                    'error_description' => sprintf('Scope \'%s\' appears more than once.', $scope),
                ]
            );
        }
    }

    /**
     * @param string $scope
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkScopeCharset(string $scope)
    {
        if (1 !== preg_match('/^[\x20\x23-\x5B\x5D-\x7E]+$/', $scope)) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManager::ERROR_INVALID_SCOPE,
                    'error_description' => 'Scope contains illegal characters.',
                ]
            );
        }
    }
}
