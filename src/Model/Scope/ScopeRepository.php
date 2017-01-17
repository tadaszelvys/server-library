<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\Scope;

use Assert\Assertion;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;

class ScopeRepository implements ScopeRepositoryInterface
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
     * @var OAuth2ResponseFactoryManagerInterface
     */
    private $responseFactoryManager;

    /**
     * ScopeManager constructor.
     *
     * @param OAuth2ResponseFactoryManagerInterface $responseFactoryManager
     * @param array                                 $availableScopes
     */
    public function __construct(OAuth2ResponseFactoryManagerInterface $responseFactoryManager, array $availableScopes = [])
    {
        $this->availableScopes = $availableScopes;
        $this->responseFactoryManager = $responseFactoryManager;
        $this->addScopePolicy(new NoScopePolicy(), true);
    }

    /**
     * {@inheritdoc}
     */
    public function addScopePolicy(ScopePolicyInterface $scopePolicy, bool $is_default = false): ScopeRepositoryInterface
    {
        $name = $scopePolicy->name();
        $this->scopePolicies[$name] = $scopePolicy;

        if (true === $is_default) {
            $this->defaultScopePolicy = $name;
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedScopePolicies(): array
    {
        return array_keys($this->scopePolicies);
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function getAvailableScopesForClient(Client $client): array
    {
        return ($client->has('scope')) ? $this->convertToArray($client->get('scope')) : $this->getSupportedScopes();
    }

    /**
     * {@inheritdoc}
     */
    public function getScopePolicyForClient(Client $client): ScopePolicyInterface
    {
        if ($client->has('scope_policy') && null !== $policyName = $client->get('scope_policy')) {
            return $this->getScopePolicy($policyName);
        }

        return $this->getDefaultScopePolicy();
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function areRequestScopesAvailable(array $requestedScopes, array $availableScopes): bool
    {
        return 0 === count(array_diff($requestedScopes, $availableScopes));
    }

    /**
     * {@inheritdoc}
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
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE,
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
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE,
                    'error_description' => 'Scope contains illegal characters.',
                ]
            );
        }
    }
}
