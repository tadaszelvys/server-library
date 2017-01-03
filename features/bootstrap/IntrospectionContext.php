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

class IntrospectionContext extends BaseContext
{
    use ResponseTrait;

    /**
     * @Given An unauthenticated protected resource tries to get information about a token
     */
    public function anUnauthenticatedProtectedResourceTriesToGetInformationAboutAToken()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->setResponse($this->getApplication()->getTokenIntrospectionPipe()->dispatch($request));
    }

    /**
     * @Given A protected resource sends an invalid introspection request
     */
    public function aProtectedResourceSendsAnInvalidIntrospectionRequest()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenIntrospectionPipe()->dispatch($request));
    }

    /**
     * @Then no token revocation event is thrown
     */
    public function noTokenRevocationEventIsThrown()
    {
        throw new PendingException();
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
