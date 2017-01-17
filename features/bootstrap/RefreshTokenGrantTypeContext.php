<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Behat\Behat\Hook\Scope\BeforeScenarioScope;

class RefreshTokenGrantTypeContext extends BaseContext
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
     * @Given A client sends a Refresh Token Grant Type request without refresh_token parameter
     */
    public function aClientSendsARefreshTokenGrantTypeRequestWithoutRefreshTokenParameter()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'refresh_token',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a Refresh Token Grant Type request with an expired refresh token
     */
    public function aClientSendsARefreshTokenGrantTypeRequestWithAnExpiredRefreshToken()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'    => 'refresh_token',
            'refresh_token' => 'EXPIRED_REFRESH_TOKEN',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a valid Refresh Token Grant Type request
     */
    public function aClientSendsAValidRefreshTokenGrantTypeRequest()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'    => 'refresh_token',
            'refresh_token' => 'VALID_REFRESH_TOKEN',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    /**
     * @Given A client sends a valid Refresh Token Grant Type request but the grant type is not allowed
     */
    public function aClientSendsAValidRefreshTokenGrantTypeRequestButTheGrantTypeIsNotAllowed()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type'    => 'refresh_token',
            'refresh_token' => 'NOT IMPORTANT',
            'client_id'     => 'client2',
        ]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }
}
