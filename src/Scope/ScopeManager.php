<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Scope;

use Assert\Assertion;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ScopeExtensionInterface;
use OAuth2\Exception\ExceptionManagerInterface;

class ScopeManager implements ScopeManagerInterface
{
    use HasExceptionManager;

    /**
     * @var string[]
     */
    private $available_scopes;

    /**
     * @var \OAuth2\Scope\ScopePolicyInterface[]
     */
    private $scope_policies = [];

    /**
     * @var string
     */
    private $default_scope_policy;

    /**
     * ScopeManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     * @param array                                       $available_scopes
     */
    public function __construct(ExceptionManagerInterface $exception_manager, array $available_scopes = [])
    {
        $this->available_scopes = $available_scopes;
        $this->setExceptionManager($exception_manager);
        $this->addScopePolicy(new NoScopePolicy(), true);
    }

    /**
     * {@inheritdoc}
     */
    public function addScopePolicy(ScopePolicyInterface $scope_policy, $is_default = false)
    {
        $name = $scope_policy->getName();
        if (!$this->hasScopePolicy($name)) {
            $this->scope_policies[$name] = $scope_policy;
        }

        if (true === $is_default) {
            $this->default_scope_policy = $name;
        }
    }

    /**
     * @param string $scope_policy_name
     *
     * @return string
     */
    private function hasScopePolicy($scope_policy_name)
    {
        return array_key_exists($scope_policy_name, $this->scope_policies);
    }

    /**
     * @param string $scope_policy_name
     *
     * @return \OAuth2\Scope\ScopePolicyInterface
     */
    private function getScopePolicy($scope_policy_name)
    {
        Assertion::keyExists($this->scope_policies, $scope_policy_name, sprintf('The scope policy with name "%s" is not supported', $scope_policy_name));

        return $this->scope_policies[$scope_policy_name];
    }

    /**
     * @return string[]
     */
    public function getAvailableScopes()
    {
        return $this->available_scopes;
    }

    /**
     * @return string
     */
    public function getDefaultScopePolicy()
    {
        return $this->scope_policies[$this->default_scope_policy];
    }

    /**
     * {@inheritdoc}
     */
    public function getAvailableScopesForClient(ClientInterface $client)
    {
        return ($client instanceof ScopeExtensionInterface && null !== $client->getAvailableScopes()) ? $client->getAvailableScopes() : $this->getAvailableScopes();
    }

    /**
     * {@inheritdoc}
     */
    public function getScopePolicyForClient(ClientInterface $client)
    {
        if ($client instanceof ScopeExtensionInterface && null !== $policy_name = $client->getScopePolicy()) {
            return $this->getScopePolicy($policy_name);
        }

        return $this->getDefaultScopePolicy();
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(array $scope, ClientInterface $client)
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
    public function checkScopes(array $requestedScopes, array $availableScopes)
    {
        return 0 === count(array_diff($requestedScopes, $availableScopes));
    }

    /**
     * {@inheritdoc}
     */
    public function convertToArray($scopes)
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
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkScopeUsedOnce($scope, array $scopes)
    {
        if (1 < count(array_keys($scopes, $scope))) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_SCOPE, sprintf('Scope "%s" appears more than once.', $scope));
        }
    }

    /**
     * @param string $scope
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkScopeCharset($scope)
    {
        if (1 !== preg_match('/^[\x20\x23-\x5B\x5D-\x7E]+$/', $scope)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_SCOPE, 'Scope contains illegal characters.');
        }
    }
}
