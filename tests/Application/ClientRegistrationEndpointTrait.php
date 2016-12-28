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
use OAuth2\Endpoint\ClientRegistration\ClientRegistrationEndpoint;
use OAuth2\Middleware\InitialAccessTokenMiddleware;
use OAuth2\Middleware\Pipe;
use OAuth2\Response\OAuth2ExceptionMiddleware;
use SimpleBus\Message\Bus\Middleware\MessageBusSupportingMiddleware;

trait ClientRegistrationEndpointTrait
{
    abstract public function getOAuth2ResponseMiddleware(): OAuth2ExceptionMiddleware;

    abstract public function getInitialAccessTokenMiddleware(): InitialAccessTokenMiddleware;

    abstract public function getResponseFactory(): ResponseFactoryInterface;

    abstract public function getStreamFactory(): StreamFactoryInterface;

    abstract public function getCommandBus(): MessageBusSupportingMiddleware;

    /**
     * @var null|ClientRegistrationEndpoint
     */
    private $clientRegistrationEndpoint = null;

    /**
     * @return ClientRegistrationEndpoint
     */
    public function getClientRegistrationEndpoint(): ClientRegistrationEndpoint
    {
        if (null === $this->clientRegistrationEndpoint) {
            $this->clientRegistrationEndpoint = new ClientRegistrationEndpoint(
                $this->getResponseFactory(),
                $this->getStreamFactory(),
                $this->getCommandBus()
            );
        }

        return $this->clientRegistrationEndpoint;
    }

    /**
     * @var null|Pipe
     */
    private $clientRegistrationPipe = null;

    /**
     * @return Pipe
     */
    public function getClientRegistrationPipe(): Pipe
    {
        if (null === $this->clientRegistrationPipe) {
            $this->clientRegistrationPipe = new Pipe();

            $this->clientRegistrationPipe->appendMiddleware($this->getOAuth2ResponseMiddleware());
            $this->clientRegistrationPipe->appendMiddleware($this->getInitialAccessTokenMiddleware());
            $this->clientRegistrationPipe->appendMiddleware($this->getClientRegistrationEndpoint());
        }

        return $this->clientRegistrationPipe;
    }
}
