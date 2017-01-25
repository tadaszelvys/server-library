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
use OAuth2\Model\Client\Client;
use OAuth2\Model\Scope\ScopeRepository;
use OAuth2\Response\OAuth2ResponseFactoryManager;

class ScopeParameterChecker implements ParameterCheckerInterface
{
    /**
     * @var ScopeRepository
     */
    private $scopeRepository;

    /**
     * @param ScopeRepository $scopeRepository
     */
    public function __construct(ScopeRepository $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(Client $client, array &$parameters)
    {
        $scope = $this->scopeRepository->checkScopePolicy($parameters['scope'], $client);
        $available_scope = $this->scopeRepository->getAvailableScopesForClient($client);
        Assertion::true($this->scopeRepository->areRequestScopesAvailable($scope, $available_scope), sprintf('An unsupported scope was requested. Available scopes for the client are %s', implode(',', $available_scope)));
        $parameters['scope'] = $scope;
    }

    /**
     * {@inheritdoc}
     */
    public function getError(): string
    {
        return OAuth2ResponseFactoryManager::ERROR_INVALID_SCOPE;
    }
}
