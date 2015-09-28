<?php

namespace OAuth2\Scope;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ScopeExtensionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class ScopeManager implements ScopeManagerInterface
{
    use HasExceptionManager;

    /**
     * @return string[]
     */
    abstract public function getScopes();

    /**
     * @return string[]
     */
    abstract public function getDefault();

    /**
     * @return string
     */
    abstract public function getPolicy();

    protected static function supportedPolicies()
    {
        return [null, self::POLICY_MODE_DEFAULT, self::POLICY_MODE_ERROR];
    }

    /**
     * {@inheritdoc}
     */
    public function getAvailableScopes(ClientInterface $client = null, ServerRequestInterface $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && null !== ($client->getAvailableScopes($request))) ? $client->getAvailableScopes($request) : $this->getScopes();
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultScopes(ClientInterface $client = null, ServerRequestInterface $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && null !== ($client->getDefaultScopes($request))) ? $client->getDefaultScopes($request) : $this->getDefault();
    }

    /**
     * {@inheritdoc}
     */
    public function getScopePolicy(ClientInterface $client = null, ServerRequestInterface $request = null)
    {
        return ($client instanceof ScopeExtensionInterface && null !== ($client->getScopePolicy($request))) ? $client->getScopePolicy($request) : $this->getPolicy();
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(ClientInterface $client, array $scope, ServerRequestInterface $request = null)
    {
        $policy = $this->getScopePolicy($client, $request);
        if (!in_array($policy, self::supportedPolicies(), true)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The policy must be one of these values: '.json_encode(self::supportedPolicies()));
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
     * {@inheritdoc}
     */
    public function convertToScope($scopes)
    {
        if (empty($scopes)) {
            return [];
        } elseif (is_array($scopes)) {
            return $scopes;
        } elseif (!is_string($scopes)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The parameter must be null,a string or an array of strings.');
        }
        $scopes = explode(' ', $scopes);

        $result = [];
        foreach ($scopes as $scope) {
            $this->checkScopeCharset($scope);
            $this->checkScopeUsedOnce($scope, $scopes);
            $result[] = $scope;
        }

        return $result;
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
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_SCOPE, sprintf('Scope "%s" appears more than once.', $scope));
        }
    }

    /**
     * @param string $scope
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkScopeCharset($scope)
    {
        if (1 !== preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scope)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_SCOPE, 'Scope contains illegal characters.');
        }
    }
}
