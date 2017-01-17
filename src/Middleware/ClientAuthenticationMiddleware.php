<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Middleware;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ClientAuthenticationMiddleware implements MiddlewareInterface
{
    /**
     * @var TokenEndpointAuthMethodManagerInterface
     */
    private $tokenEndpointAuthMethodManager;

    /**
     * ClientAuthenticationMiddleware constructor.
     *
     * @param TokenEndpointAuthMethodManagerInterface $tokenEndpointAuthMethodManager
     */
    public function __construct(TokenEndpointAuthMethodManagerInterface $tokenEndpointAuthMethodManager)
    {
        $this->tokenEndpointAuthMethodManager = $tokenEndpointAuthMethodManager;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $client = $this->tokenEndpointAuthMethodManager->findClient($request);
        if (null !== $client) {
            $request = $request->withAttribute('client', $client);
        }

        return $delegate->process($request);
    }
}
