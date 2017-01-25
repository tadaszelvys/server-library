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

use Assert\Assertion;
use Behat\Behat\Context\Context;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use Behat\Gherkin\Node\PyStringNode;
use Psr\Http\Message\ResponseInterface;

class ResponseContext implements Context
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
     * @var ApplicationContext
     */
    private $applicationContext;

    /**
     * @BeforeScenario
     *
     * @param BeforeScenarioScope $scope
     */
    public function gatherContexts(BeforeScenarioScope $scope)
    {
        $environment = $scope->getEnvironment();

        $this->applicationContext = $environment->getContext('ApplicationContext');
    }

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
        $this->rewind();
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
            Assertion::greaterThan(count($headers), 0);
            $header = $headers[0];
            preg_match_all('/(\w+\*?)="((?:[^"\\\\]|\\\\.)+)"|([^\s,$]+)/', substr($header, strpos($header, ' ')), $matches, PREG_SET_ORDER);
            if (!is_array($matches)) {
                throw new \InvalidArgumentException('Unable to parse header');
            }
            foreach ($matches as $match) {
                $this->error[$match[1]] = $match[2];
            }
        } else {
            $this->rewind();
            $response = (string) $this->getResponse()->getBody()->getContents();
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
     * @Then no access token creation event is thrown
     */
    public function noAccessTokenCreationEventIsThrown()
    {
        $events = $this->applicationContext->getApplication()->getAccessTokenCreatedEventHandler()->getEvents();
        Assertion::eq(0, count($events));
    }

    /**
     * @Then the response contains an access token
     */
    public function theResponseContainsAnAccessToken()
    {
        $this->rewind();
        $content = (string) $this->getResponse()->getBody()->getContents();
        $data = json_decode($content, true);
        Assertion::isArray($data);
        Assertion::keyExists($data, 'access_token');
    }

    /**
     * @Then an access token creation event is thrown
     */
    public function anAccessTokenCreationEventIsThrown()
    {
        $events = $this->applicationContext->getApplication()->getAccessTokenCreatedEventHandler()->getEvents();
        Assertion::greaterThan(count($events), 0);
    }

    /**
     * @Then I show the OAuth2 Response
     */
    public function iShowTheOauth2Response()
    {
        $this->rewind();
        $content = (string) $this->getResponse()->getBody()->getContents();

        dump(json_decode($content, true));
    }

    /**
     * @Then the response contains something like :pattern
     */
    public function theResponseContainsSomethingLike($pattern)
    {
        $this->rewind();
        $content = (string) $this->getResponse()->getBody()->getContents();
        Assertion::regex($content, $pattern);
    }

    /**
     * @Then the content type of the response is :content_type
     */
    public function theContentTypeOfTheResponseIs($content_type)
    {
        Assertion::eq($content_type, $this->getResponse()->getHeader('Content-Type'));
    }

    private function rewind()
    {
        if (true === $this->getResponse()->getBody()->isSeekable()) {
            $this->getResponse()->getBody()->rewind();
        }
    }
}
