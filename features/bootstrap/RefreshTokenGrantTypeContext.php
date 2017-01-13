<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Behat\Behat\Tester\Exception\PendingException;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use OAuth2\Model\Client\ClientId;

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
        throw new PendingException();
    }

    /**
     * @Given a client sends a Refresh Token Grant Type request with an expired refresh token
     */
    public function aClientSendsARefreshTokenGrantTypeRequestWithAnExpiredRefreshToken()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid Refresh Token Grant Type request
     */
    public function aClientSendsAValidRefreshTokenGrantTypeRequest()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid Refresh Token Grant Type request but the grant type is not allowed
     */
    public function aClientSendsAValidRefreshTokenGrantTypeRequestButTheGrantTypeIsNotAllowed()
    {
        throw new PendingException();
    }
}
