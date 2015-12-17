<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManager as Base;

class ScopeManager extends Base
{
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
    private $policy;

    /**
     * ClientCredentialsGrantType constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        parent::__construct($exception_manager);

        $this->available_scopes = [
            'scope1',
            'scope2',
            'scope3',
            'scope4',
        ];
        $this->default_scopes = [
            'scope1',
            'scope2',
        ];
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
     * @param string[] $available_scopes
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
     * @param string[] $default_scopes
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
}
