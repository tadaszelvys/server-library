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

class ResourceOwnerPasswordCredentialsGrantTypeContext extends BaseContext
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
     * @Given A client sends a Resource Owner Password Credentials Grant Type request without username parameter
     */
    public function aClientSendsAResourceOwnerPasswordCredentialsGrantTypeRequestWithoutUsernameParameter()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a Resource Owner Password Credentials Grant Type request without password parameter
     */
    public function aClientSendsAResourceOwnerPasswordCredentialsGrantTypeRequestWithoutPasswordParameter()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a Resource Owner Password Credentials Grant Type request with invalid user credentials
     */
    public function aClientSendsAResourceOwnerPasswordCredentialsGrantTypeRequestWithInvalidUserCredentials()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid Resource Owner Password Credentials Grant Type request
     */
    public function aClientSendsAValidResourceOwnerPasswordCredentialsGrantTypeRequest()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid Resource Owner Password Credentials Grant Type request but the grant type is not allowed
     */
    public function aClientSendsAValidResourceOwnerPasswordCredentialsGrantTypeRequestButTheGrantTypeIsNotAllowed()
    {
        throw new PendingException();
    }
}
