<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Psr\Http\Message\ResponseInterface;
use Behat\Gherkin\Node\PyStringNode;
use Assert\Assertion;
use Behat\Behat\Tester\Exception\PendingException;

class ResponseContext  extends BaseContext
{
    /**
     * @var null|ResponseInterface
     */
    private $response = null;

    /**
     * @var null|array
     */
    private $error = null;

    /**
     * @param ResponseInterface $response
     */
    public function setResponse(ResponseInterface $response)
    {
        $this->response = $response;
        if ($this->response->getBody()->isSeekable()) {
            $this->response->getBody()->rewind();
        }
    }

    /**
     * @return ResponseInterface
     */
    public function getResponse(): ResponseInterface
    {
        return $this->response;
    }

    /**
     * @Then the response code is :code
     */
    public function theResponseCodeIs($code)
    {
        Assertion::eq((int) $code, $this->getResponse()->getStatusCode());
    }

    /**
     * @Then the response contains
     */
    public function theResponseContains(PyStringNode $response)
    {
        Assertion::eq($response->getRaw(), (string) $this->getResponse()->getBody()->getContents());
    }

    /**
     * @Then the response contains an error with code :code
     */
    public function theResponseContainsAnError($code)
    {
        Assertion::eq((int) $code, $this->getResponse()->getStatusCode());
        Assertion::greaterOrEqualThan($this->getResponse()->getStatusCode(), 400);
        if (401 === $this->getResponse()->getStatusCode()) {
            $headers = $this->getResponse()->getHeader('WWW-Authenticate');
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
            $response = $this->getResponse()->getBody()->getContents();
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
     * @Then the client should be redirected
     */
    public function theClientShouldBeRedirected()
    {
        Assertion::eq(302, $this->getResponse()->getStatusCode());
        $header = $this->getResponse()->getHeaders();
        Assertion::keyExists($header, 'Location');
        $location = $header['Location'];
        Assertion::true(!empty($location));
    }

    /**
     * @Then the redirect Uri contains an error
     */
    public function theRedirectUriContainsAnError()
    {
        throw new PendingException();
    }

    /**
     * @Then no access token creation event is thrown
     */
    public function noAccessTokenCreationEventIsThrown()
    {
        throw new PendingException();
    }

    /**
     * @Then the response contains an access token
     */
    public function theResponseContainsAnAccessToken()
    {
        throw new PendingException();
    }

    /**
     * @Then an access token creation event is thrown
     */
    public function anAccessTokenCreationEventIsThrown()
    {
        throw new PendingException();
    }
}
