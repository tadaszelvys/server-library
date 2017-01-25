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
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager;

final class TokenEndpointAuthMethodEndpointRule implements RuleInterface
{
    /**
     * @var TokenEndpointAuthMethodManager
     */
    private $tokenEndpointAuthMethodManager;

    /**
     * TokenEndpointAuthMethodEndpointRule constructor.
     *
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager $tokenEndpointAuthMethodManager
     */
    public function __construct(TokenEndpointAuthMethodManager $tokenEndpointAuthMethodManager)
    {
        $this->tokenEndpointAuthMethodManager = $tokenEndpointAuthMethodManager;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        Assertion::keyExists($commandParameters, 'token_endpoint_auth_method', 'The parameter \'token_endpoint_auth_method\' is missing.');
        Assertion::string($commandParameters['token_endpoint_auth_method'], 'The parameter \'token_endpoint_auth_method\' must be a string.');
        Assertion::true($this->tokenEndpointAuthMethodManager->hasTokenEndpointAuthMethod($commandParameters['token_endpoint_auth_method']), sprintf('The token endpoint authentication method \'%s\' is not supported. Please use one of the following values: %s', $commandParameters['token_endpoint_auth_method'], implode(', ', $this->tokenEndpointAuthMethodManager->getSupportedTokenEndpointAuthMethods())));

        $token_endpoint_auth_method = $this->tokenEndpointAuthMethodManager->getTokenEndpointAuthMethod($commandParameters['token_endpoint_auth_method']);
        $token_endpoint_auth_method->checkClientConfiguration($commandParameters, $validatedParameters);

        $validatedParameters['token_endpoint_auth_method'] = $commandParameters['token_endpoint_auth_method'];

        return $next($commandParameters, $validatedParameters, $userAccountId);
    }
}
