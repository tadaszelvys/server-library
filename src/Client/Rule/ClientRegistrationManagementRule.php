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
use OAuth2\Model\UserAccount\UserAccount;

abstract class ClientRegistrationManagementRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        Assertion::keyExists($validated_parameters, 'client_id', 'The parameter \'client_id\' is not defined.');
        $validated_parameters['registration_access_token'] = $this->generateRegistrationAccessToken();
        $validated_parameters['registration_client_uri'] = $this->getRegistrationClientUri($validated_parameters['client_id']);

        return $next($command_parameters, $validated_parameters, $userAccount);
    }

    /**
     * @param string $clientId
     *
     * @return string
     */
    abstract protected function getRegistrationClientUri(string $clientId);

    /**
     * @return string
     */
    abstract protected function generateRegistrationAccessToken();
}
