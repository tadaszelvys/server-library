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

class AuthorizationCodeGrantTypeContext implements Context
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
     * @Given A client sends a Authorization Code Grant Type request but the code parameter is missing
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButTheCodeParameterIsMissing()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'authorization_code',
            'scope'      => 'openid email phone address',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a Authorization Code Grant Type request but the redirection Uri parameter is missing
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButTheRedirectionUriParameterIsMissing()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'authorization_code',
            'code'       => 'VALID_AUTH_CODE',
            'scope'      => 'openid email phone address',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a Authorization Code Grant Type request but the redirection Uri parameter mismatch
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButTheRedirectionUriParameterMismatch()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'   => 'authorization_code',
            'code'         => 'VALID_AUTH_CODE',
            'redirect_uri' => 'http://127.0.0.1/',
            'scope'        => 'openid email phone address',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a valid Authorization Code Grant Type request
     */
    public function aClientSendsAValidAuthorizationCodeGrantTypeRequest()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'   => 'authorization_code',
            'code'         => 'VALID_AUTH_CODE',
            'redirect_uri' => 'https://www.example.com/callback',
            'scope'        => 'openid email phone address',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Then an authorization code used event is thrown
     */
    public function anAuthorizationCodeUsedEventIsThrown()
    {
        $events = $this->applicationContext->getApplication()->getAuthCodeMarkedAsUsedEventHandler()->getEvents();
        Assertion::greaterThan(count($events), 0);
    }

    /**
     * @Given A client sends a valid Authorization Code Grant Type request with reduced scope
     */
    public function aClientSendsAValidAuthorizationCodeGrantTypeRequestWithReducedScope()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'   => 'authorization_code',
            'code'         => 'VALID_AUTH_CODE',
            'redirect_uri' => 'https://www.example.com/callback',
            'scope'        => 'openid',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a Authorization Code Grant Type request but a scope is not allowed
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButAScopeIsNotAllowed()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'   => 'authorization_code',
            'code'         => 'VALID_AUTH_CODE',
            'redirect_uri' => 'https://www.example.com/callback',
            'scope'        => 'openid write',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a Authorization Code Grant Type request but a authorization code is for another client
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButAAuthorizationCodeIsForAnotherClient()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'   => 'authorization_code',
            'code'         => 'VALID_AUTH_CODE',
            'redirect_uri' => 'https://www.example.com/callback',
            'scope'        => 'openid',
            'client_id'    => 'client2',
        ]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a Authorization Code Grant Type request but the authorization code expired
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButTheAuthorizationCodeExpired()
    {
        $request = $this->applicationContext->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'   => 'authorization_code',
            'code'         => 'EXPIRED_AUTH_CODE',
            'redirect_uri' => 'https://www.example.com/callback',
            'scope'        => 'openid',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->applicationContext->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a Authorization Code Grant Type request but the authorization code requires a code_verifier parameter
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButTheAuthorizationCodeRequiresACodeVerifierParameter()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a Authorization Code Grant Type request but the code_verifier parameter of the authorization code is invalid
     */
    public function aClientSendsAAuthorizationCodeGrantTypeRequestButTheCodeVerifierParameterOfTheAuthorizationCodeIsInvalid()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid Authorization Code Grant Type request with code verifier that uses plain method
     */
    public function aClientSendsAValidAuthorizationCodeGrantTypeRequestWithCodeVerifierThatUsesPlainMethod()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid Authorization Code Grant Type request with code verifier that uses S256 method
     */
    public function aClientSendsAValidAuthorizationCodeGrantTypeRequestWithCodeVerifierThatUsesSMethod()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a authorization requests with the Authorization Code Response Type
     */
    public function aClientSendsAAuthorizationRequestsWithTheAuthorizationCodeResponseType()
    {
        throw new PendingException();
    }

    /**
     * @When the Resource Owner accepts the authorization request
     */
    public function theResourceOwnerAcceptsTheAuthorizationRequest()
    {
        throw new PendingException();
    }

    /**
     * @Then the redirection Uri starts with :arg1
     */
    public function theRedirectionUriStartsWith($arg1)
    {
        throw new PendingException();
    }

    /**
     * @Then the redirection Uri query should contain a parameter :arg1
     */
    public function theRedirectionUriQueryShouldContainAParameter($arg1)
    {
        throw new PendingException();
    }

    /**
     * @Then an authorization code creation event is thrown
     */
    public function anAuthorizationCodeCreationEventIsThrown()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a authorization requests with the Authorization Code Response Type and a code verifier
     */
    public function aClientSendsAAuthorizationRequestsWithTheAuthorizationCodeResponseTypeAndACodeVerifier()
    {
        throw new PendingException();
    }

    /**
     * @When the Resource Owner rejects the authorization request
     */
    public function theResourceOwnerRejectsTheAuthorizationRequest()
    {
        throw new PendingException();
    }

    /**
     * @Then the redirection ends with :arg1
     */
    public function theRedirectionEndsWith($arg1)
    {
        throw new PendingException();
    }

    /**
     * @Then the redirect query should contain parameter :arg1 with value :arg2
     */
    public function theRedirectQueryShouldContainParameterWithValue($arg1, $arg2)
    {
        throw new PendingException();
    }
}
