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

abstract class ClientRegistrationManagementRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        Assertion::keyExists($validatedParameters, 'client_id', 'The parameter \'client_id\' is not defined.');
        $validatedParameters['registration_access_token'] = $this->generateRegistrationAccessToken();
        $validatedParameters['registration_client_uri'] = $this->getRegistrationClientUri($validatedParameters['client_id']);

        return $next($commandParameters, $validatedParameters, $userAccountId);
    }

    /**
     * @param string $clientId
     *
     * @return string
     */
    abstract protected function getRegistrationClientUri(string $clientId): string;

    /**
     * @return string
     */
    abstract protected function generateRegistrationAccessToken(): string;
}
