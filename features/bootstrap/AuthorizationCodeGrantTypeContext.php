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

class AuthorizationCodeGrantTypeContext implements Context
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
     * @Given a valid authorization code request is received and the resource owner accepts it
     */
    public function aValidAuthorizationCodeRequestIsReceivedAndTheResourceOwnerAcceptsIt()
    {
        throw new PendingException();
    }

    /**
     * @Then the redirect Uri contains an authorization code
     */
    public function theRedirectUriContainsAnAuthorizationCode()
    {
        throw new PendingException();
    }

    /**
     * @Given a public client sends a request without code verification parameter
     */
    public function aPublicClientSendsARequestWithoutCodeVerificationParameter()
    {
        throw new PendingException();
    }

    /**
     * @Given a public client sends a request with an invalid code verification parameter
     */
    public function aPublicClientSendsARequestWithAnInvalidCodeVerificationParameter()
    {
        throw new PendingException();
    }

    /**
     * @Given a valid authorization code grant is received
     */
    public function aValidAuthorizationCodeGrantIsReceived()
    {
        throw new PendingException();
    }
}
