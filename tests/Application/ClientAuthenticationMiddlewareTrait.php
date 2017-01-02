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

use OAuth2\Middleware\ClientAuthenticationMiddleware;
use OAuth2\Test\Stub\ClientAssertionJwt;
use OAuth2\Test\Stub\ClientRepository;
use OAuth2\Test\Stub\ClientSecretBasic;
use OAuth2\Test\Stub\ClientSecretPost;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager;

trait ClientAuthenticationMiddlewareTrait
{
    abstract public function getClientRepository(): ClientRepository;

    /**
     * @var null|ClientAuthenticationMiddleware
     */
    private $clientAuthenticationMiddleware = null;

    /**
     * @return ClientAuthenticationMiddleware
     */
    public function getClientAuthenticationMiddleware(): ClientAuthenticationMiddleware
    {
        if (null === $this->clientAuthenticationMiddleware) {
            $this->clientAuthenticationMiddleware = new ClientAuthenticationMiddleware(
                $this->getTokenEndpointAuthMethodManager()
            );
        }

        return $this->clientAuthenticationMiddleware;
    }

    /**
     * @var null|TokenEndpointAuthMethodManager
     */
    private $tokenEndpointAuthMethodManager = null;

    /**
     * @return TokenEndpointAuthMethodManager
     */
    public function getTokenEndpointAuthMethodManager(): TokenEndpointAuthMethodManager
    {
        if (null === $this->tokenEndpointAuthMethodManager) {
            $this->tokenEndpointAuthMethodManager = new TokenEndpointAuthMethodManager(
                $this->getClientRepository()
            );
            $this->tokenEndpointAuthMethodManager->addTokenEndpointAuthMethod(new ClientSecretBasic('My service'));
            $this->tokenEndpointAuthMethodManager->addTokenEndpointAuthMethod(new ClientSecretPost());
            $this->tokenEndpointAuthMethodManager->addTokenEndpointAuthMethod(new ClientAssertionJwt(
                $this->getJwtLoader()
            ));
        }

        return $this->tokenEndpointAuthMethodManager;
    }
}
