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

use Assert\Assertion;
use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Behat\Tester\Exception\PendingException;

class OIDCContext implements Context
{
    /**
     * @var ResponseContext
     */
    private $responseContext;

    /**
     * @var ApplicationContext
     */
    private $applicationContext;

    /**
     * @BeforeScenario
     *
     * @param BeforeScenarioScope $scope
     */
    public function gatherContexts(BeforeScenarioScope $scope)
    {
        $environment = $scope->getEnvironment();

        $this->responseContext = $environment->getContext('ResponseContext');
        $this->applicationContext = $environment->getContext('ApplicationContext');
    }

    /**
     * @When a client send a Userinfo request without access token
     */
    public function aClientSendAUserinfoRequestWithoutAccessToken()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getUserInfoEndpointPipe()->dispatch($request));
    }

    /**
     * @When a client sends a valid Userinfo request
     */
    public function aClientSendsAValidUserinfoRequest()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withHeader('Authorization', 'Bearer VALID_ACCESS_TOKEN_FOR_USERINFO');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getUserInfoEndpointPipe()->dispatch($request));
    }

    /**
     * @When a client sends a Userinfo request but the access token has no openid scope
     */
    public function aClientSendsAUserinfoRequestButTheAccessTokenHasNoOpenidScope()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withHeader('Authorization', 'Bearer INVALID_ACCESS_TOKEN_FOR_USERINFO');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getUserInfoEndpointPipe()->dispatch($request));
    }

    /**
     * @When a client sends a Userinfo request but the access token has not been issued through the authorization endpoint
     */
    public function aClientSendsAUserinfoRequestButTheAccessTokenHasNotBeenIssuedThroughTheAuthorizationEndpoint()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withHeader('Authorization', 'Bearer ACCESS_TOKEN_ISSUED_THROUGH_TOKEN_ENDPOINT');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getUserInfoEndpointPipe()->dispatch($request));
    }
}
