<?php

declare(strict_types=1);

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
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManager;
use Psr\Http\Message\ServerRequestInterface;

final class OAuth2ExceptionMiddleware implements MiddlewareInterface
{
    /**
     * @var OAuth2ResponseFactoryManager
     */
    private $auth2ResponseFactoryManager;

    /**
     * OAuth2ExceptionMiddleware constructor.
     *
     * @param OAuth2ResponseFactoryManager $auth2ResponseFactoryManager
     */
    public function __construct(OAuth2ResponseFactoryManager $auth2ResponseFactoryManager)
    {
        $this->auth2ResponseFactoryManager = $auth2ResponseFactoryManager;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        try {
            return $delegate->process($request);
        } catch (OAuth2Exception $e) {
            $oauth2Response = $this->auth2ResponseFactoryManager->getResponse(
                $e->getCode(),
                $e->getData()
            );

            return $oauth2Response->getResponse();
        }
    }
}
