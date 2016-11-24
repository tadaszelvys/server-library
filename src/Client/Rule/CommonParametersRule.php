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
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\UserAccount\UserAccount;

final class CommonParametersRule extends AbstractInternationalizedRule
{
    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        foreach ($this->getSupportedParameters() as $parameter => $closure) {
            $validated_parameters = array_merge(
                $validated_parameters,
                $this->getInternationalizedParameters($command_parameters, $parameter, $closure)
            );
        }

        return $next($command_parameters, $validated_parameters, $userAccount);
    }

    /**
     * @return array
     */
    private function getSupportedParameters()
    {
        return [
            'client_name' => function ($k, $v) {
            },
            'client_uri'  => $this->getUriVerificationClosure(),
            'logo_uri'    => $this->getUriVerificationClosure(),
            'tos_uri'     => $this->getUriVerificationClosure(),
            'policy_uri'  => $this->getUriVerificationClosure(),
        ];
    }

    private function getUriVerificationClosure()
    {
        return function ($k, $v) {
            Assertion::url($v, sprintf('The parameter with key \'%s\' is not a valid URL.', $k));
        };
    }
}
