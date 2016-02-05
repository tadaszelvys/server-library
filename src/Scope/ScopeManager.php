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
use Psr\Http\Message\ServerRequestInterface;

abstract class ScopeManager implements ScopeManagerInterface
{
    use HasExceptionManager;

    /**
     * @var string[]
     */
    private $available_scopes;

    /**
     * @var string[]
     */
    private $default_scopes;

    /**
     * @var string
     */
    private $scope_policy = self::POLICY_MODE_NONE;

    /**
     * ScopeManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     * @param array                                       $available_scopes
     * @param array                                       $default_scopes
     * @param null                                        $scope_policy
     */
    public function __construct(
        ExceptionManagerInterface $exception_manager,
        array $available_scopes,
        array $default_scopes = [],
        $scope_policy = self::POLICY_MODE_NONE
    ) {
        Assertion::nullOrString($scope_policy);

        $this->available_scopes = $available_scopes;
        $this->default_scopes = $default_scopes;
        $this->scope_policy = $scope_policy;
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @return string[]
     */
    private function getAvailableScopes()
    {
        return $this->available_scopes;
    }

    /**
     * @return string[]
     */
    private function getDefaultScopes()
    {
        return $this->default_scopes;
    }

    /**
     * @return string
     */
    private function getScopePolicy()
    {
        return $this->scope_policy;
    }

    /**
     * {@inheritdoc}
     */
    public static function supportedPolicies()
    {
        return [
            self::POLICY_MODE_NONE,
            self::POLICY_MODE_DEFAULT,
            self::POLICY_MODE_ERROR,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getAvailableScopesForClient(ClientInterface $client = null, ServerRequestInterface $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && null !== $client->getAvailableScopes($request)) ? $client->getAvailableScopes($request) : $this->getAvailableScopes();
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultScopesForClient(ClientInterface $client = null, ServerRequestInterface $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && null !== $client->getDefaultScopes($request)) ? $client->getDefaultScopes($request) : $this->getDefaultScopes();
    }

    /**
     * {@inheritdoc}
     */
    public function getScopePolicyForClient(ClientInterface $client = null, ServerRequestInterface $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && null !== $client->getScopePolicy($request)) ? $client->getScopePolicy($request) : $this->getScopePolicy();
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(ClientInterface $client, array $scope, ServerRequestInterface $request = null)
    {
        $policy = $this->getScopePolicyForClient($client, $request);

        // If Scopes Policy is set to "error" and no scope is set, then throws an error
        if (empty($scope) && self::POLICY_MODE_ERROR === $policy) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_SCOPE, 'No scope was requested.');
        }

        // If Scopes Policy is set to "default" and no scope is set, then application or client defaults are set
        if (empty($scope) && self::POLICY_MODE_DEFAULT === $policy) {
            return $this->getDefaultScopesForClient($client, $request);
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
    public function getScope($scope)
    {
        $scope = new Scope($scope);

        return $scope;
    }

    /**
     * {@inheritdoc}
     */
    public function convertToScope(array $scopes)
    {
        $result = [];
        foreach ($scopes as $scope) {
            $object = $this->getScope($scope);
            $result[] = $object;
        }

        return $result;
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
