<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use Base64Url\Base64Url;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasTokenEndpointAuthMethod;
use OAuth2\Client\AuthenticationMethod\AuthenticationMethodInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class ClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasTokenEndpointAuthMethod;

    /**
     * ClientManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function createClient()
    {
        $client = new Client();
        $client->setPublicId(Base64Url::encode(random_bytes(50)));
        $client->set('grant_types', ['authorization_code']);
        $client->set('response_types', ['code']);
        $client->set('token_endpoint_auth_method', 'client_basic_secret');
        $client->set('secret', Base64Url::encode(random_bytes(30)));

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request)
    {
        $client_id = $this->findClientInTheRequest($request, $authentication_method, $client_credentials);

        if (null !== $client_id) {
            $client = $this->getClient($client_id);
            if ($client instanceof ClientInterface && true === $this->isClientAuthenticated($request, $client, $authentication_method, $client_credentials)) {
                return $client;
            }
        }

        throw $this->buildAuthenticationException($request);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface                          $request
     * @param \OAuth2\Client\AuthenticationMethod\AuthenticationMethodInterface $authentication_method
     * @param mixed                                                             $client_credentials    The client credentials found in the request
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return null|string
     */
    private function findClientInTheRequest(ServerRequestInterface $request, &$authentication_method, &$client_credentials = null)
    {
        $client_id = null;
        $client_credentials = null;
        foreach ($this->getAuthenticationMethods() as $method) {
            $temp = $method->findClient($request, $client_credentials);
            if (null !== $temp) {
                if (null !== $client_id) {
                    $authentication_method = null;
                    throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
                } else {
                    $client_id = $temp;
                    $authentication_method = $method;
                }
            }
        }

        return $client_id;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface                          $request
     * @param \OAuth2\Client\ClientInterface                                    $client
     * @param \OAuth2\Client\AuthenticationMethod\AuthenticationMethodInterface $authentication_method
     * @param mixed|null                                                        $client_credentials
     *
     * @return true
     */
    public function isClientAuthenticated(ServerRequestInterface $request, ClientInterface $client, AuthenticationMethodInterface $authentication_method, $client_credentials)
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
        foreach ($this->getAuthenticationMethods() as $method) {
            $scheme = $method->getSchemesParameters();
            $schemes = array_merge($schemes, $scheme);
        }

        return $this->getExceptionManager()->getAuthenticateException(
            ExceptionManagerInterface::INVALID_CLIENT,
            $message,
            ['schemes' => $schemes]
        );
    }
}
