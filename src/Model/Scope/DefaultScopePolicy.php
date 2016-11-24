<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\Scope;

use OAuth2\Model\Client\Client;

class DefaultScopePolicy implements ScopePolicyInterface
{
    /**
     * @var string[]
     */
    private $defaultScopes;

    /**
     * DefaultScopePolicy constructor.
     *
     * @param string[] $defaultScopes
     */
    public function __construct(array $defaultScopes)
    {
        $this->defaultScopes = $defaultScopes;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'default';
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(array &$scope, Client $client)
    {
        $scope = $this->getDefaultScopesForClient($client);
    }

    /**
     * @return string[]
     */
    private function getDefaultScopes(): array
    {
        return $this->defaultScopes;
    }

    /**
     * @param Client $client
     * @return \string[]
     */
    private function getDefaultScopesForClient(Client $client): array
    {
        return ($client->has('default_scope')) && null !== $client->get('default_scope') ? $client->get('default_scope') : $this->getDefaultScopes();
    }
}
