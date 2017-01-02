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
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Endpoint\TokenRevocation\TokenRevocationPostEndpoint;
use OAuth2\Middleware\ClientAuthenticationMiddleware;
use OAuth2\Middleware\HttpMethod;
use OAuth2\Middleware\Pipe;
use OAuth2\Response\OAuth2ExceptionMiddleware;
use OAuth2\TokenTypeHint\AccessTokenTypeHint;
use SimpleBus\Message\Bus\Middleware\MessageBusSupportingMiddleware;
use OAuth2\Endpoint\TokenRevocation\TokenRevocationGetEndpoint;

trait TokenRevocationEndpointTrait
{
    abstract public function getAccessTokenRepository(): AccessTokenRepositoryInterface;

    abstract public function getOAuth2ResponseMiddleware(): OAuth2ExceptionMiddleware;

    abstract public function getResponseFactory(): ResponseFactoryInterface;

    abstract public function getCommandBus(): MessageBusSupportingMiddleware;

    abstract public function getClientAuthenticationMiddleware(): ClientAuthenticationMiddleware;

    /**
     * @var null|TokenRevocationGetEndpoint
     */
    private $tokenRevocationGetEndpoint = null;

    /**
     * @return TokenRevocationGetEndpoint
     */
    public function getTokenRevocationGetEndpoint(): TokenRevocationGetEndpoint
    {
        if (null === $this->tokenRevocationGetEndpoint) {
            $this->tokenRevocationGetEndpoint = new TokenRevocationGetEndpoint();
            $this->tokenRevocationGetEndpoint->addTokenTypeHint($this->getAccessTokenTypeHint()); // Access Token
            //$this->tokenRevocationGetEndpoint->addTokenTypeHint(); // Refresh Token
            //$this->tokenRevocationGetEndpoint->addTokenTypeHint(); // Auth Code
        }

        return $this->tokenRevocationGetEndpoint;
    }

    /**
     * @var null|TokenRevocationPostEndpoint
     */
    private $tokenRevocationPostEndpoint = null;

    /**
     * @return TokenRevocationPostEndpoint
     */
    public function getTokenRevocationPostEndpoint(): TokenRevocationPostEndpoint
    {
        if (null === $this->tokenRevocationPostEndpoint) {
            $this->tokenRevocationPostEndpoint = new TokenRevocationPostEndpoint();
            $this->tokenRevocationPostEndpoint->addTokenTypeHint($this->getAccessTokenTypeHint()); // Access Token
            //$this->tokenRevocationPostEndpoint->addTokenTypeHint(); // Refresh Token
            //$this->tokenRevocationPostEndpoint->addTokenTypeHint(); // Auth Code
        }

        return $this->tokenRevocationPostEndpoint;
    }

    /**
     * @var null|Pipe
     */
    private $tokenRevocationPipe = null;

    /**
     * @return Pipe
     */
    public function getTokenRevocationPipe(): Pipe
    {
        if (null === $this->tokenRevocationPipe) {
            $this->tokenRevocationPipe = new Pipe();

            $this->tokenRevocationPipe->appendMiddleware($this->getOAuth2ResponseMiddleware());
            $this->tokenRevocationPipe->appendMiddleware($this->getClientAuthenticationMiddleware());
            $this->tokenRevocationPipe->appendMiddleware($this->getTokenRevocationHttpMethod());
        }

        return $this->tokenRevocationPipe;
    }

    /**
     * @var null|HttpMethod
     */
    private $tokenRevocationHttpMethod = null;

    /**
     * @return HttpMethod
     */
    public function getTokenRevocationHttpMethod(): HttpMethod
    {
        if (null === $this->tokenRevocationHttpMethod) {
            $this->tokenRevocationHttpMethod = new HttpMethod(
                $this->getResponseFactory()
            );
            $this->tokenRevocationHttpMethod->addMiddleware('POST', $this->getTokenRevocationPostEndpoint());
            $this->tokenRevocationHttpMethod->addMiddleware('GET', $this->getTokenRevocationGetEndpoint());
        }

        return $this->tokenRevocationHttpMethod;
    }

    /**
     * @var null|AccessTokenTypeHint
     */
    private $accessTokenTypeHint = null;

    /**
     * @return AccessTokenTypeHint
     */
    public function getAccessTokenTypeHint(): AccessTokenTypeHint
    {
        if (null === $this->accessTokenTypeHint) {
            $this->accessTokenTypeHint = new AccessTokenTypeHint(
                $this->getAccessTokenRepository(),
                $this->getCommandBus(),
                true
            );
        }

        return $this->accessTokenTypeHint;
    }
}
