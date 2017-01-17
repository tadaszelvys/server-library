<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Behat\Tester\Exception\PendingException;
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
     * @Given An client sends a JWT Bearer Grant Type request without assertion
     */
    public function anClientSendsAJwtBearerGrantTypeRequestWithoutAssertion()
    {
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
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
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion'  => $this->generateValidAssertion(),
            //'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            //'client_assertion'      => $this->generateValidClientAssertion(),
        ]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->responseContext->setResponse($this->getApplication()->getTokenEndpointPipe()->dispatch($request));
    }

    private function generateValidAssertion()
    {
        $claims = [
            'iss' => 'client3',
            'sub' => 'client3',
            'aud' => 'My Server',
            'jti' => Base64Url::encode(random_bytes(64)),
            'exp' => (new \DateTimeImmutable('now + 1 day'))->getTimestamp(),
        ];
        $headers = [
            'alg' => 'HS256',
        ];
        $client = $this->getApplication()->getClientRepository()->find(ClientId::create('client3'));

        return $this->getApplication()->getJwTCreator()->sign($claims, $headers, $client->getPublicKeySet()->getKey(0));
    }
}
