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

class JwtBearerGrantTypeContext extends BaseContext
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
     * @Given An unauthenticated client sends a JWT Bearer Grant Type request
     */
    public function anUnauthenticatedClientSendsAJwtBearerGrantTypeRequest()
    {
        throw new PendingException();
    }

    /**
     * @Given An client sends a JWT Bearer Grant Type request without assertion
     */
    public function anClientSendsAJwtBearerGrantTypeRequestWithoutAssertion()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid JWT Bearer Grant Type request
     */
    public function aClientSendsAValidJwtBearerGrantTypeRequest()
    {
        throw new PendingException();
    }

    /**
     * @Given A client sends a valid JWT Bearer Grant Type request but the grant type is not allowed
     */
    public function aClientSendsAValidJwtBearerGrantTypeRequestButTheGrantTypeIsNotAllowed()
    {
        throw new PendingException();
    }
}
