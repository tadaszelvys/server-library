<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Application;

use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\Factory\StreamFactoryInterface;
use OAuth2\Response\Factory\AccessDeniedResponseFactory;
use OAuth2\Response\Factory\BadRequestResponseFactory;
use OAuth2\Response\Factory\CreatedResponseFactory;
use OAuth2\Response\Factory\MethodNotAllowedResponseFactory;
use OAuth2\Response\Factory\NoBodyResponseFactory;
use OAuth2\Response\Factory\NotImplementedResponseFactory;
use OAuth2\Response\Factory\SuccessResponseFactory;
use OAuth2\Response\OAuth2ExceptionMiddleware;
use OAuth2\Response\OAuth2ResponseFactoryManager;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\Test\Stub\AuthenticateResponseFactory;

trait OAuth2ResponseFactoryTrait
{
    abstract public function getResponseFactory(): ResponseFactoryInterface;

    abstract public function getStreamFactory(): StreamFactoryInterface;

    /**
     * @var null|OAuth2ResponseFactoryManagerInterface
     */
    private $oauth2ResponseFactory = null;
    private $oauth2ResponseMiddleware = null;

    /**
     * @return OAuth2ResponseFactoryManagerInterface
     */
    public function getOAuth2ResponseFactory(): OAuth2ResponseFactoryManagerInterface
    {
        if (null === $this->oauth2ResponseFactory) {
            $this->oauth2ResponseFactory = new OAuth2ResponseFactoryManager(
                $this->getResponseFactory(),
                $this->getStreamFactory()
            );

            $this->oauth2ResponseFactory->addResponseFactory(new AuthenticateResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new AccessDeniedResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new BadRequestResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new CreatedResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new MethodNotAllowedResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new NoBodyResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new NotImplementedResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new SuccessResponseFactory());
        }

        return $this->oauth2ResponseFactory;
    }

    /**
     * @return OAuth2ExceptionMiddleware
     */
    public function getOAuth2ResponseMiddleware(): OAuth2ExceptionMiddleware
    {
        if (null === $this->oauth2ResponseMiddleware) {
            $this->oauth2ResponseMiddleware = new OAuth2ExceptionMiddleware(
                $this->getOAuth2ResponseFactory()
            );
        }

        return $this->oauth2ResponseMiddleware;
    }
}
