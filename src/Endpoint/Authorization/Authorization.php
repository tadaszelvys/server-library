<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\ResponseMode\ResponseModeInterface;
use OAuth2\User\UserInterface;

final class Authorization implements AuthorizationInterface
{
    /**
     * @var bool
     */
    private $is_authorized;

    /**
     * @var \OAuth2\Client\ClientInterface
     */
    private $client;

    /**
     * @var \OAuth2\User\UserInterface
     */
    private $user;

    /**
     * @var array
     */
    private $scopes = [];

    /**
     * @var array
     */
    private $data = [];

    /**
     * @var \OAuth2\Grant\ResponseTypeInterface[]
     */
    private $response_types = [];

    /**
     * @var \OAuth2\ResponseMode\ResponseModeInterface
     */
    private $response_mode = null;

    /**
     * @var array
     */
    private $query_params = [];

    /**
     * @var string
     */
    private $redirect_uri;

    /**
     * Authorization constructor.
     *
     * @param array                                      $query_params
     * @param \OAuth2\Client\ClientInterface             $client
     * @param \OAuth2\Grant\ResponseTypeInterface[]      $response_types
     * @param \OAuth2\ResponseMode\ResponseModeInterface $response_mode
     * @param string                                     $redirect_uri
     * @param string[]                                   $scopes
     */
    public function __construct(array $query_params,
                                ClientInterface $client,
                                array $response_types,
                                ResponseModeInterface $response_mode,
                                $redirect_uri,
                                array $scopes
    ) {
        $this->scopes = $scopes;
        $this->client = $client;
        $this->query_params = $query_params;
        $this->response_mode = $response_mode;
        $this->response_types = $response_types;
        $this->redirect_uri = $redirect_uri;
    }

    /**
     * {@inheritdoc}
     */
    public function setUser(UserInterface $user)
    {
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * {@inheritdoc}
     */
    public function getQueryParams()
    {
        return $this->query_params;
    }

    /**
     * {@inheritdoc}
     */
    public function getPrompt()
    {
        if (!$this->hasQueryParam('prompt')) {
            return [];
        }

        return $this->getQueryParam('prompt');
    }

    /**
     * {@inheritdoc}
     */
    public function hasPrompt($prompt)
    {
        Assertion::string($prompt);

        return in_array($prompt, $this->getPrompt());
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function hasScope($scope)
    {
        Assertion::string($scope);

        return null !== $this->scopes && in_array($scope, $this->scopes);
    }

    /**
     * {@inheritdoc}
     */
    public function unsetScope($scope)
    {
        if (true === $this->hasScope($scope)) {
            unset($this->scopes[array_search($scope, $this->scopes)]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthorized()
    {
        return $this->is_authorized;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthorized($is_authorized)
    {
        Assertion::boolean($is_authorized);

        $this->is_authorized = $is_authorized;
    }

    /**
     * {@inheritdoc}
     */
    public function hasQueryParam($param)
    {
        Assertion::string($param);

        return array_key_exists($param, $this->query_params);
    }

    /**
     * {@inheritdoc}
     */
    public function getQueryParam($param)
    {
        Assertion::string($param);
        Assertion::true($this->hasQueryParam($param), sprintf('Invalid parameter "%s"', $param));

        return $this->query_params[$param];
    }

    /**
     * {@inheritdoc}
     */
    public function hasData($key)
    {
        Assertion::string($key);

        return array_key_exists($key, $this->data);
    }

    /**
     * {@inheritdoc}
     */
    public function getData($key)
    {
        Assertion::string($key);
        Assertion::true($this->hasData($key), sprintf('Invalid data "%s"', $key));

        return $this->data[$key];
    }

    /**
     * {@inheritdoc}
     */
    public function setData($key, $data)
    {
        Assertion::string($key);
        $this->data[$key] = $data;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypes()
    {
        return $this->response_types;
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return $this->response_mode;
    }
}
