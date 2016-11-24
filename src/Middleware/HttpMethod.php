<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Middleware;

use Assert\Assertion;
use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;

final class HttpMethod implements MiddlewareInterface
{
    /**
     * @var MiddlewareInterface[]
     */
    private $methodMap = [];

    /**
     * @var array|ResponseFactoryInterface
     */
    private $responseFactory = [];

    /**
     * HttpMethod constructor.
     * @param ResponseFactoryInterface $responseFactory
     */
    public function __construct(ResponseFactoryInterface $responseFactory)
    {
        $this->responseFactory = $responseFactory;
    }

    /**
     * @param string $method
     * @param MiddlewareInterface $middleware
     */
    public function addMiddleware(string $method, MiddlewareInterface $middleware)
    {
        Assertion::keyNotExists($this->methodMap, $method, sprintf('The method \'%s\' is already defined.', $method));
        $this->methodMap[$method] = $middleware;
    }

    /**
     * @inheritdoc
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $method = $request->getMethod();

        if (!array_key_exists($method, $this->methodMap)) {
            return $this->responseFactory->createResponse(405);
        }

        $middleware = $this->methodMap[$method];

        return $middleware->process($request, $delegate);
    }
}
