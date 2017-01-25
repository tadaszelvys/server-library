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

namespace OAuth2\Middleware;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager;
use Psr\Http\Message\ServerRequestInterface;

final class ClientAuthenticationMiddleware implements MiddlewareInterface
{
    /**
     * @var TokenEndpointAuthMethodManager
     */
    private $tokenEndpointAuthMethodManager;

    /**
     * @var bool
     */
    private $authenticationRequired;

    /**
     * ClientAuthenticationMiddleware constructor.
     *
     * @param TokenEndpointAuthMethodManager $tokenEndpointAuthMethodManager
     * @param bool                                    $authenticationRequired
     */
    public function __construct(TokenEndpointAuthMethodManager $tokenEndpointAuthMethodManager, bool $authenticationRequired)
    {
        $this->tokenEndpointAuthMethodManager = $tokenEndpointAuthMethodManager;
        $this->authenticationRequired = $authenticationRequired;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $client = $this->tokenEndpointAuthMethodManager->findClient($request);
        if (null !== $client) {
            $request = $request->withAttribute('client', $client);
        } else {
            if (true === $this->authenticationRequired) {
                throw new OAuth2Exception(
                    401,
                    [
                        'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                        'error_description' => 'Client authentication failed.',
                    ]
                );
            }
        }

        return $delegate->process($request);
    }
}
