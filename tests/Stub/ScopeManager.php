<?php

namespace OAuth2\Test\Stub;

use OAuth2\Scope\ScopeManager as Base;

class ScopeManager extends Base
{
    /**
     * @var \OAuth2\Scope\ScopeInterface[]
     */
    private $available_scopes;

    /**
     * @var \OAuth2\Scope\ScopeInterface[]
     */
    private $default_scopes;

    /**
     * @var string
     */
    private $policy;

    public function __construct()
    {
        $this->available_scopes = array(
            $this->createScope('scope1'),
            $this->createScope('scope2'),
            $this->createScope('scope3'),
            $this->createScope('scope4'),
        );
        $this->default_scopes = array(
            $this->createScope('scope1'),
            $this->createScope('scope2'),
        );
        $this->policy = 'default';
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes()
    {
        return $this->available_scopes;
    }

    /**
     * @param \OAuth2\Scope\ScopeInterface[] $available_scopes
     *
     * @return self
     */
    public function setScopes(array $available_scopes)
    {
        $this->available_scopes = $available_scopes;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefault()
    {
        return $this->default_scopes;
    }

    /**
     * @param \OAuth2\Scope\ScopeInterface[] $default_scopes
     *
     * @return self
     */
    public function setDefault(array $default_scopes)
    {
        $this->default_scopes = $default_scopes;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getPolicy()
    {
        return $this->policy;
    }

    /**
     * @param string $policy
     *
     * @return self
     */
    public function setPolicy($policy)
    {
        $this->policy = $policy;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function createScope($name)
    {
        $scope = new Scope();
        $scope->setName($name);

        return $scope;
    }
}
