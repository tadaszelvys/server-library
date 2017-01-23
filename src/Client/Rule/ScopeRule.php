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

namespace OAuth2\Client\Rule;

use Assert\Assertion;
use OAuth2\Model\Scope\ScopeRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccountId;

final class ScopeRule implements RuleInterface
{
    /**
     * @var ScopeRepositoryInterface
     */
    private $scopeManager;

    /**
     * @param ScopeRepositoryInterface $scopeManager
     */
    public function __construct(ScopeRepositoryInterface $scopeManager)
    {
        $this->scopeManager = $scopeManager;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccountId $userAccountId, callable $next)
    {
        if (array_key_exists('scope', $command_parameters)) {
            Assertion::regex($command_parameters['scope'], '/^[\x20\x23-\x5B\x5D-\x7E]+$/', 'Invalid characters found in the \'scope\' parameter.');
            $validated_parameters['scope'] = $command_parameters['scope'];
        }
        if (array_key_exists('scope_policy', $command_parameters)) {
            Assertion::inArray($command_parameters['scope_policy'], $this->scopeManager->getSupportedScopePolicies(), sprintf('The scope policy \'%s\' is not supported. Please choose one of the following policy: \'%s\'.', $command_parameters['scope_policy'], implode(', ', $this->scopeManager->getSupportedScopePolicies())));
            $validated_parameters['scope_policy'] = $command_parameters['scope_policy'];
        }

        /*
         * Should be handled by the scope policy itself
         */
        if (array_key_exists('default_scope', $command_parameters)) {
            Assertion::regex($command_parameters['default_scope'], '/^[\x20\x23-\x5B\x5D-\x7E]+$/', 'Invalid characters found in the \'default_scope\' parameter.');
            $validated_parameters['default_scope'] = $command_parameters['default_scope'];
        }

        return $next($command_parameters, $validated_parameters, $userAccountId);
    }
}
