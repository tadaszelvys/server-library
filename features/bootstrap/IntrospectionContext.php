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

use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Behat\Tester\Exception\PendingException;

class IntrospectionContext implements Context
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
     * @Given An unauthenticated protected resource tries to get information about a token
     */
    public function anUnauthenticatedProtectedResourceTriesToGetInformationAboutAToken()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenIntrospectionPipe()->dispatch($request));
    }

    /**
     * @Given A protected resource sends an invalid introspection request
     */
    public function aProtectedResourceSendsAnInvalidIntrospectionRequest()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenIntrospectionPipe()->dispatch($request));
    }

    /**
     * @Given A protected resource tries to get information of a token that owns another protected resource
     */
    public function aProtectedResourceTriesToGetInformationOfATokenThatOwnsAnotherProtectedResource()
    {
        throw new PendingException();
    }

    /**
     * @Given A protected resource tries to get information of a token
     */
    public function aProtectedResourceTriesToGetInformationOfAToken()
    {
        throw new PendingException();
    }
}
