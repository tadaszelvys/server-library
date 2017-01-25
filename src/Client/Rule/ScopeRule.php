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
use OAuth2\Model\Scope\ScopeRepository;
use OAuth2\Model\UserAccount\UserAccountId;

final class ScopeRule implements RuleInterface
{
    /**
     * @var ScopeRepository
     */
    private $scopeManager;

    /**
     * @param ScopeRepository $scopeManager
     */
    public function __construct(ScopeRepository $scopeManager)
    {
        $this->scopeManager = $scopeManager;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        if (array_key_exists('scope', $commandParameters)) {
            Assertion::regex($commandParameters['scope'], '/^[\x20\x23-\x5B\x5D-\x7E]+$/', 'Invalid characters found in the \'scope\' parameter.');
            $validatedParameters['scope'] = $commandParameters['scope'];
        }
        if (array_key_exists('scope_policy', $commandParameters)) {
            Assertion::inArray($commandParameters['scope_policy'], $this->scopeManager->getSupportedScopePolicies(), sprintf('The scope policy \'%s\' is not supported. Please choose one of the following policy: \'%s\'.', $commandParameters['scope_policy'], implode(', ', $this->scopeManager->getSupportedScopePolicies())));
            $validatedParameters['scope_policy'] = $commandParameters['scope_policy'];
        }

        /*
         * Should be handled by the scope policy itself
         */
        if (array_key_exists('default_scope', $commandParameters)) {
            Assertion::regex($commandParameters['default_scope'], '/^[\x20\x23-\x5B\x5D-\x7E]+$/', 'Invalid characters found in the \'default_scope\' parameter.');
            $validatedParameters['default_scope'] = $commandParameters['default_scope'];
        }

        return $next($commandParameters, $validatedParameters, $userAccountId);
    }
}
