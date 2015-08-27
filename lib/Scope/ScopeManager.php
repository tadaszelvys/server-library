<?php

namespace OAuth2\Scope;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ScopeExtensionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Symfony\Component\HttpFoundation\Request;

abstract class ScopeManager implements ScopeManagerInterface
{
    use HasExceptionManager;

    /**
     * @return \OAuth2\Scope\ScopeInterface[]
     */
    abstract public function getScopes();

    /**
     * @return \OAuth2\Scope\ScopeInterface[]
     */
    abstract public function getDefault();

    /**
     * @return string
     */
    abstract public function getPolicy();

    /**
     * Create a ScopeInterface object.
     *
     * @param string $name Name of the scope to create
     *
     * @return ScopeInterface A ScopeInterface object
     */
    abstract public function createScope($name);

    protected static function supportedPolicies()
    {
        return [null, self::POLICY_MODE_DEFAULT, self::POLICY_MODE_ERROR];
    }

    /**
     * {@inheritdoc}
     */
    public function getAvailableScopes(ClientInterface $client = null, Request $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && !is_null($client->getAvailableScopes($request))) ? $client->getAvailableScopes($request) : $this->getScopes();
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultScopes(ClientInterface $client = null, Request $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && !is_null($client->getDefaultScopes($request))) ? $client->getDefaultScopes($request) : $this->getDefault();
    }

    /**
     * {@inheritdoc}
     */
    public function getScopePolicy(ClientInterface $client = null, Request $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && !is_null($client->getScopePolicy($request))) ? $client->getScopePolicy($request) : $this->getPolicy();
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(ClientInterface $client, array $scope, Request $request = null)
    {
        $policy = $this->getScopePolicy($client, $request);
        if (!in_array($policy, self::supportedPolicies(), true)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'invalid_scope_policy', 'The policy must be one of these values: '.json_encode(self::supportedPolicies()));
        }

        // If Scopes Policy is set to "error" and no scope is set, then throws an error
        if (empty($scope) && self::POLICY_MODE_ERROR === $policy) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_SCOPE, 'No scope was requested.');
        }

        // If Scopes Policy is set to "default" and no scope is set, then application or client defaults are set
        if (empty($scope) && self::POLICY_MODE_DEFAULT === $policy) {
            return $this->getDefaultScopes($client, $request);
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
     * @param array $scopes
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    private function convertArrayToScope(array $scopes)
    {
        $result = [];
        foreach ($scopes as $scope) {
            if ($scope instanceof ScopeInterface) {
                $result[] = $scope;
            } elseif (is_string($scope) || is_array($scope)) {
                $result = array_merge($result, $this->convertToScope($scope));
            } else {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'invalid_parameter', 'The parameter must be null,a string or an array of ScopeInterface objects.');
            }
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function convertToScope($scopes)
    {
        if (empty($scopes)) {
            return [];
        }
        if (is_array($scopes)) {
            return $this->convertArrayToScope($scopes);
        }
        if (!is_string($scopes)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'invalid_parameter', 'The parameter must be null,a string or an array of ScopeInterface objects.');
        }
        $scopes = explode(' ', $scopes);

        $result = [];
        foreach ($scopes as $scope) {
            if (1 !== preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scope)) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_SCOPE, 'Scope contains illegal characters.');
            }
            $result[] = $this->createScope($scope);
        }

        return $result;
    }
}
