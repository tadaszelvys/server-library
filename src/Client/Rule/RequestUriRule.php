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
use OAuth2\Model\UserAccount\UserAccount;

final class RequestUriRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        if (array_key_exists('request_uris', $command_parameters)) {
            Assertion::isArray($command_parameters['request_uris'], 'The parameter \'request_uris\' must be a list of URI.');
            Assertion::allUrl($command_parameters['request_uris'], 'The parameter \'request_uris\' must be a list of URI.');
            $validated_parameters['request_uris'] = $command_parameters['request_uris'];
        }

        return $next($command_parameters, $validated_parameters, $userAccount);
    }
}
