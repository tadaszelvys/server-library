<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Behat\Behat\Tester\Exception\PendingException;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;

class ClientCredentialsGrantTypeContext extends BaseContext
{
    /**
     * @var ResponseContext
     */
    private $responseContext;

    /**
     * @BeforeScenario
     *
     * @param BeforeScenarioScope $scope
     */
    public function gatherContexts(BeforeScenarioScope $scope)
    {
        $environment = $scope->getEnvironment();

        $this->responseContext = $environment->getContext('ResponseContext');
    }

    /**
     * @Given An unauthenticated client sends a Client Credentials Grant Type request
     */
    public function anUnauthenticatedClientSendsAClientCredentialsGrantTypeRequest()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'client_credentials',
        ]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given An public client sends a Client Credentials Grant Type request
     */
    public function anPublicClientSendsAClientCredentialsGrantTypeRequest()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'client_credentials',
        ]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        $request = $request->withHeader('X-OAuth2-Public-Client-ID', 'client2');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a valid Client Credentials Grant Type request
     */
    public function aClientSendsAValidClientCredentialsGrantTypeRequest()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'client_credentials',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client authenticated with a JWT assertion sends a valid Client Credentials Grant Type request
     */
    public function aClientAuthenticatedWithAJwtAssertionSendsAValidClientCredentialsGrantTypeRequest()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid Client Credentials Grant Type request but the grant type is not allowed
     */
    public function aClientSendsAValidClientCredentialsGrantTypeRequestButTheGrantTypeIsNotAllowed()
    {
        throw new PendingException();
    }
}
