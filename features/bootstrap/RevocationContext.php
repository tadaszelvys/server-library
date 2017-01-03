<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Assert\Assertion;
use OAuth2\Event\AccessToken\AccessTokenRevokedEvent;
use OAuth2\Event\RefreshToken\RefreshTokenRevokedEvent;

class RevocationContext extends BaseContext
{
    use ResponseTrait;

    /**
     * @Given a client sends a POST revocation request but it is not authenticated
     */
    public function aClientSendsAPostRevocationRequestButItIsNotAuthenticated()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a GET revocation request but it is not authenticated
     */
    public function aClientSendsAGetRevocationRequestButItIsNotAuthenticated()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([]);

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a POST revocation request without token parameter
     */
    public function aClientSendsAPostRevocationRequestWithoutTokenParameter()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a GET revocation request without token parameter
     */
    public function aClientSendsAGetRevocationRequestWithoutTokenParameter()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a POST revocation request without token parameter with a callback parameter
     */
    public function aClientSendsAPostRevocationRequestWithoutTokenParameterWithACallbackParameter()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'callback' => 'foo'
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a GET revocation request without token parameter with a callback parameter
     */
    public function aClientSendsAGetRevocationRequestWithoutTokenParameterWithACallbackParameter()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([
            'callback' => 'foo'
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a valid POST revocation request
     */
    public function aClientSendsAValidPostRevocationRequest()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'token' => 'ACCESS_TOKEN_#1'
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a valid GET revocation request
     */
    public function aClientSendsAValidGetRevocationRequest()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([
            'token' => 'ACCESS_TOKEN_#1'
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a valid POST revocation request but the token owns to another client
     */
    public function aClientSendsAValidPostRevocationRequestButTheTokenOwnsToAnotherClient()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'token' => 'ACCESS_TOKEN_#2'
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a valid GET revocation request but the token owns to another client
     */
    public function aClientSendsAValidGetRevocationRequestButTheTokenOwnsToAnotherClient()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([
            'token' => 'ACCESS_TOKEN_#2'
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a POST revocation request but the token type hint is not supported
     */
    public function aClientSendsAPostRevocationRequestButTheTokenTypeHintIsNotSupported()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'token' => 'ACCESS_TOKEN_#2',
            'token_type_hint' => 'bad_hint',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a GET revocation request but the token type hint is not supported
     */
    public function aClientSendsAGetRevocationRequestButTheTokenTypeHintIsNotSupported()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([
            'token' => 'ACCESS_TOKEN_#2',
            'token_type_hint' => 'bad_hint',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a POST revocation request but the token does not exist or expired
     */
    public function aClientSendsAPostRevocationRequestButTheTokenDoesNotExistOrExpired()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([
            'token' => 'UNKNOWN_REFRESH_TOKEN_#2',
            'token_type_hint' => 'refresh_token',
        ]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a GET revocation request but the token does not exist or expired
     */
    public function aClientSendsAGetRevocationRequestButTheTokenDoesNotExistOrExpired()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([
            'token' => 'UNKNOWN_REFRESH_TOKEN_#2',
            'token_type_hint' => 'refresh_token',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Given a client sends a GET revocation request with callback but the token does not exist or expired
     */
    public function aClientSendsAGetRevocationRequestWithCallbackButTheTokenDoesNotExistOrExpired()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('GET');
        $request = $request->withQueryParams([
            'token' => 'UNKNOWN_REFRESH_TOKEN_#2',
            'token_type_hint' => 'refresh_token',
            'callback' => 'callback',
        ]);
        $request = $request->withHeader('Authorization', 'Basic '.base64_encode('client1:secret'));

        $this->setResponse($this->getApplication()->getTokenRevocationPipe()->dispatch($request));
    }

    /**
     * @Then no token revocation event is thrown
     */
    public function noTokenRevocationEventIsThrown()
    {
        $events = $this->getApplication()->getEventStore()->all();
        Assertion::eq(0, count($events));
    }

    /**
     * @Then a token revocation event is thrown
     */
    public function aTokenRevocationEventIsThrown()
    {
        $events = $this->getApplication()->getEventStore()->all();
        Assertion::eq(2, count($events));
        Assertion::isInstanceOf(array_values($events)[0], AccessTokenRevokedEvent::class);
        Assertion::isInstanceOf(array_values($events)[1], RefreshTokenRevokedEvent::class);
    }
}
