<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\Rule;

use Assert\Assertion;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Scope\ScopeManagerInterface;

class ScopeRule implements RuleInterface
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
    public function check(ClientInterface $client, array $registration_parameters)
    {
        if (!$this->hasScopeManager()) {
            return;
        }
        if (array_key_exists('scope', $registration_parameters)) {
            Assertion::regex($registration_parameters['scope'], '/^[\x20\x23-\x5B\x5D-\x7E]+$/', 'Invalid characters found in the "scope" parameter.');
            $client->set('scope', $registration_parameters['scope']);
        }
        if (array_key_exists('scope_policy', $registration_parameters)) {
            Assertion::inArray($registration_parameters['scope_policy'], $this->getScopeManager()->getSupportedScopePolicies(), sprintf('The scope policy "%s" is not supported. Please choose one of the following policy: "%s".', $registration_parameters['scope_policy'], json_encode($this->getScopeManager()->getSupportedScopePolicies())));
            $client->set('scope_policy', $registration_parameters['scope_policy']);
        }

        /*
         * Should be handled by the scope policy itself
         */
        if (array_key_exists('default_scope', $registration_parameters)) {
            Assertion::regex($registration_parameters['default_scope'], '/^[\x20\x23-\x5B\x5D-\x7E]+$/', 'Invalid characters found in the "default_scope" parameter.');
            $client->set('default_scope', $registration_parameters['default_scope']);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getPreserverParameters()
    {
        return [];
    }
}
