<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenEndpointAuthMethod;

namespace OAuth2\TokenEndpointAuthMethod;

use Assert\Assertion;
use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenEndpointAuthMethodManager implements TokenEndpointAuthMethodManagerInterface
{
    use HasClientManager;
    use HasExceptionManager;

    /**
     * @var \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface[]
     */
    private $token_endpoint_auth_names = [];

    /**
     * @var \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface[]
     */
    private $token_endpoint_auth_methods = [];

    public function __construct(ClientManagerInterface $client_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setClientManager($client_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function addTokenEndpointAuthMethod(TokenEndpointAuthMethodInterface $token_endpoint_auth_method)
    {
        $this->token_endpoint_auth_methods[] = $token_endpoint_auth_method;
        foreach ($token_endpoint_auth_method->getSupportedAuthenticationMethods() as $method_name) {
            $this->token_endpoint_auth_names[$method_name] = $token_endpoint_auth_method;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTokenEndpointAuthMethods()
    {
        return array_keys($this->token_endpoint_auth_names);
    }

    /**
     * {@inheritdoc}
     */
    public function hasTokenEndpointAuthMethod($token_endpoint_auth_method)
    {
        return array_key_exists($token_endpoint_auth_method, $this->token_endpoint_auth_names);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenEndpointAuthMethod($token_endpoint_auth_method)
    {
        Assertion::true($this->hasTokenEndpointAuthMethod($token_endpoint_auth_method), sprintf('The token endpoint authentication method "%s" is not supported. Please use one of the following values: %s', $token_endpoint_auth_method, json_encode($this->getSupportedTokenEndpointAuthMethods())));

        return $this->token_endpoint_auth_names[$token_endpoint_auth_method];
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenEndpointAuthMethods()
    {
        return array_values($this->token_endpoint_auth_methods);
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request)
    {
        $client_id = $this->findClientInTheRequest($request, $authentication_method, $client_credentials);

        if (null !== $client_id) {
            $client = $this->getClientManager()->getClient($client_id);
            if ($client instanceof ClientInterface && true === $this->isClientAuthenticated($request, $client, $authentication_method, $client_credentials)) {
                return $client;
            }
        }

        throw $this->buildAuthenticationException($request);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface                         $request
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface $authentication_method
     * @param mixed                                                            $client_credentials    The client credentials found in the request
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return null|string
     */
    private function findClientInTheRequest(ServerRequestInterface $request, &$authentication_method, &$client_credentials = null)
    {
        $client_id = null;
        $client_credentials = null;
        foreach ($this->getTokenEndpointAuthMethods() as $method) {
            $temp = $method->findClient($request, $client_credentials);
            if (null !== $temp) {
                if (null !== $client_id) {
                    $authentication_method = null;
                    throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
                } else {
                    $client_id = $temp;
                    $authentication_method = $method;
                }
            }
        }

        return $client_id;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface                         $request
     * @param \OAuth2\Client\ClientInterface                                   $client
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface $authentication_method
     * @param mixed|null                                                       $client_credentials
     *
     * @return true
     */
    public function isClientAuthenticated(ServerRequestInterface $request, ClientInterface $client, TokenEndpointAuthMethodInterface $authentication_method, $client_credentials)
    {
        if (in_array($client->get('token_endpoint_auth_method'), $authentication_method->getSupportedAuthenticationMethods())) {
            if (false === $client->areClientCredentialsExpired()) {
                return $authentication_method->isClientAuthenticated($client, $client_credentials, $request);
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function buildAuthenticationException(ServerRequestInterface $request)
    {
        $schemes = [];
        $message = 'Client authentication failed.';
        foreach ($this->getTokenEndpointAuthMethods() as $method) {
            $scheme = $method->getSchemesParameters();
            $schemes = array_merge($schemes, $scheme);
        }

        return $this->getExceptionManager()->getAuthenticateException(ExceptionManagerInterface::ERROR_INVALID_CLIENT, $message, ['schemes' => $schemes]);
    }
}
