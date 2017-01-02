<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Behat\Gherkin\Node\PyStringNode;
use Behat\Behat\Tester\Exception\PendingException;
use Assert\Assertion;
use OAuth2\Event\AccessToken\AccessTokenRevokedEvent;

class RevocationContext extends BaseContext
{
    /**
     * @var null|\Psr\Http\Message\ResponseInterface
     */
    private $response = null;

    /**
     * @var null|array
     */
    private $error = null;

    /**
     * @Given a client sends a POST revocation request but it is not authenticated
     */
    public function aClientSendsARevocationRequestButItIsNotAuthenticated()
    {
        /**
         * @var \Psr\Http\Message\ServerRequestInterface
         */
        $request = $this->getServerRequestFactory()->createServerRequest([]);
        $request = $request->withMethod('POST');
        $request = $request->withParsedBody([]);
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $this->response = $this->getApplication()->getTokenRevocationPipe()->dispatch($request);
        if ($this->response->getBody()->isSeekable()) {
            $this->response->getBody()->rewind();
        }
    }

    /**
     * @Given a client sends a POST revocation request without token parameter
     */
    public function aClientSendsARevocationRequestWithoutTokenParameter()
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

        $this->response = $this->getApplication()->getTokenRevocationPipe()->dispatch($request);
        if ($this->response->getBody()->isSeekable()) {
            $this->response->getBody()->rewind();
        }
    }

    /**
     * @Given a client sends a POST revocation request without token parameter with a callback parameter
     */
    public function aClientSendsARevocationRequestWithoutTokenParameterWithACallbackParameter()
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

        $this->response = $this->getApplication()->getTokenRevocationPipe()->dispatch($request);
        if ($this->response->getBody()->isSeekable()) {
            $this->response->getBody()->rewind();
        }
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

        $this->response = $this->getApplication()->getTokenRevocationPipe()->dispatch($request);
        if ($this->response->getBody()->isSeekable()) {
            $this->response->getBody()->rewind();
        }
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

        $this->response = $this->getApplication()->getTokenRevocationPipe()->dispatch($request);
        if ($this->response->getBody()->isSeekable()) {
            $this->response->getBody()->rewind();
        }
    }

    /**
     * @Then the response code is :code
     */
    public function theResponseCodeIs($code)
    {
        Assertion::eq((int) $code, $this->response->getStatusCode());
    }

    /**
     * @Then the response contains
     */
    public function theResponseContains(PyStringNode $response)
    {
        Assertion::eq($response->getRaw(), (string) $this->response->getBody()->getContents());
    }

    /**
     * @Then the response contains an error with code :code
     */
    public function theResponseContainsAnError($code)
    {
        Assertion::eq((int) $code, $this->response->getStatusCode());
        Assertion::greaterOrEqualThan($this->response->getStatusCode(), 400);
        if (401 === $this->response->getStatusCode()) {
            $headers = $this->response->getHeader('WWW-Authenticate');
            Assertion::greaterOrEqualThan(count($headers), 0);
            $header = $headers[0];
            preg_match_all('/(\w+\*?)="((?:[^"\\\\]|\\\\.)+)"|([^\s,$]+)/', substr($header, strpos($header, ' ')), $matches, PREG_SET_ORDER);
            if (!is_array($matches)) {
                throw new \InvalidArgumentException('Unable to parse header');
            }
            foreach ($matches as $match) {
                $this->error[$match[1]] = $match[2];
            }
        } else {
            $response = $this->response->getBody()->getContents();
            $json = json_decode($response, true);
            Assertion::isArray($json);
            Assertion::keyExists($json, 'error');
            $this->error = $json;
        }
    }

    /**
     * @Then the error is :error
     *
     * @param string $error
     */
    public function theErrorIs($error)
    {
        Assertion::notNull($this->error);
        Assertion::keyExists($this->error, 'error');
        Assertion::eq($error, $this->error['error']);
    }

    /**
     * @Then the error description is :errorDescription
     *
     * @param string $errorDescription
     */
    public function theErrorDescriptionIs($errorDescription)
    {
        Assertion::notNull($this->error);
        Assertion::keyExists($this->error, 'error_description');
        Assertion::eq($errorDescription, $this->error['error_description']);
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
        Assertion::eq(1, count($events));
        Assertion::allIsInstanceOf($events, AccessTokenRevokedEvent::class);
    }
}
