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
use OAuth2\Model\UserAccount\UserAccountId;

final class RedirectionUriRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccountId $userAccountId, callable $next)
    {
        if (array_key_exists('redirect_uris', $command_parameters)) {
            Assertion::isArray($command_parameters['redirect_uris'], 'The parameter \'redirect_uris\' must be a list of URI.');
            Assertion::allUrl($command_parameters['redirect_uris'], 'The parameter \'redirect_uris\' must be a list of URI.');
            $validated_parameters['redirect_uris'] = $command_parameters['redirect_uris'];
        }

        return $next($command_parameters, $validated_parameters, $userAccountId);
    }
}
