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

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use Assert\Assertion;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\Scope\ScopeManagerInterface;

class ScopeParameterChecker implements ParameterCheckerInterface
{
    use HasScopeManager;

    /**
     * @param \OAuth2\Scope\ScopeManagerInterface $scope_manager
     */
    public function __construct(ScopeManagerInterface $scope_manager)
    {
        $this->setScopeManager($scope_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        $scope = $this->getScopeManager()->checkScopePolicy($parameters['scope'], $client);
        $available_scope = $this->getScopeManager()->getAvailableScopesForClient($client);
        Assertion::true($this->getScopeManager()->areRequestScopesAvailable($scope, $available_scope), sprintf('An unsupported scope was requested. Available scopes for the client are %s', implode(',', $available_scope)));
        $parameters['scope'] = $scope;
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE;
    }
}
