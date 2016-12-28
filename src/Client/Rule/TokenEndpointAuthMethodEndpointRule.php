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
use OAuth2\Behaviour\HasTokenEndpointAuthMethodManager;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;

final class TokenEndpointAuthMethodEndpointRule implements RuleInterface
{
    use HasTokenEndpointAuthMethodManager;

    /**
     * TokenEndpointAuthMethodEndpointRule constructor.
     *
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager
     */
    public function __construct(TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager)
    {
        $this->setTokenEndpointAuthMethodManager($token_endpoint_auth_method_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        Assertion::keyExists($command_parameters, 'token_endpoint_auth_method', 'The parameter \'token_endpoint_auth_method\' is missing.');
        Assertion::string($command_parameters['token_endpoint_auth_method'], 'The parameter \'token_endpoint_auth_method\' must be a string.');
        Assertion::true($this->getTokenEndpointAuthMethodManager()->hasTokenEndpointAuthMethod($command_parameters['token_endpoint_auth_method']), sprintf('The token endpoint authentication method \'%s\' is not supported. Please use one of the following values: %s', $command_parameters['token_endpoint_auth_method'], implode(', ', $this->getTokenEndpointAuthMethodManager()->getSupportedTokenEndpointAuthMethods())));

        $token_endpoint_auth_method = $this->getTokenEndpointAuthMethodManager()->getTokenEndpointAuthMethod($command_parameters['token_endpoint_auth_method']);
        $token_endpoint_auth_method->checkClientConfiguration($command_parameters, $validated_parameters);

        $validated_parameters['token_endpoint_auth_method'] = $command_parameters['token_endpoint_auth_method'];

        return $next($command_parameters, $validated_parameters, $userAccount);
    }
}
