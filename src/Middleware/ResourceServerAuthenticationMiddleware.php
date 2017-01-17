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
use Psr\Http\Message\ServerRequestInterface;

final class ResourceServerAuthenticationMiddleware implements MiddlewareInterface
{
    /**
     * @var ResourceServerAuthMethodManagerInterface
     */
    private $resourceServerAuthMethodManager;

    /**
     * ClientAuthenticationMiddleware constructor.
     *
     * @param ResourceServerAuthMethodManagerInterface $resourceServerAuthMethodManager
     */
    public function __construct(ResourceServerAuthMethodManagerInterface $resourceServerAuthMethodManager)
    {
        $this->resourceServerAuthMethodManager = $resourceServerAuthMethodManager;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $resource_server = $this->resourceServerAuthMethodManager->findResourceServer($request);
        if (null !== $resource_server) {
            $request = $request->withAttribute('resource_server', $resource_server);
        }

        return $delegate->process($request);
    }
}
