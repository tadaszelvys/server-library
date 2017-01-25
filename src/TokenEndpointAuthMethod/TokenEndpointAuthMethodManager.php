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

namespace OAuth2\TokenEndpointAuthMethod;

use Assert\Assertion;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenEndpointAuthMethodManager
{
    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var TokenEndpointAuthMethodInterface[]
     */
    private $tokenEndpointAuthMethodNames = [];

    /**
     * @var TokenEndpointAuthMethodInterface[]
     */
    private $tokenEndpointAuthMethods = [];

    /**
     * TokenEndpointAuthMethodManager constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     */
    public function __construct(ClientRepositoryInterface $clientRepository)
    {
        $this->clientRepository = $clientRepository;
    }

    /**
     * @param TokenEndpointAuthMethodInterface $tokenEndpointAuthMethod
     *
     * @return TokenEndpointAuthMethodManager
     */
    public function addTokenEndpointAuthMethod(TokenEndpointAuthMethodInterface $tokenEndpointAuthMethod): TokenEndpointAuthMethodManager
    {
        $this->tokenEndpointAuthMethods[] = $tokenEndpointAuthMethod;
        foreach ($tokenEndpointAuthMethod->getSupportedAuthenticationMethods() as $method_name) {
            $this->tokenEndpointAuthMethodNames[$method_name] = $tokenEndpointAuthMethod;
        }

        return $this;
    }

    /**
     * @return string[]
     */
    public function getSupportedTokenEndpointAuthMethods(): array
    {
        return array_keys($this->tokenEndpointAuthMethodNames);
    }

    /**
     * @param string $tokenEndpointAuthMethod
     *
     * @return bool
     */
    public function hasTokenEndpointAuthMethod(string $tokenEndpointAuthMethod): bool
    {
        return array_key_exists($tokenEndpointAuthMethod, $this->tokenEndpointAuthMethodNames);
    }

    /**
     * @param string $tokenEndpointAuthMethod
     *
     * @throws \InvalidArgumentException
     *
     * @return TokenEndpointAuthMethodInterface
     */
    public function getTokenEndpointAuthMethod(string $tokenEndpointAuthMethod): TokenEndpointAuthMethodInterface
    {
        Assertion::true($this->hasTokenEndpointAuthMethod($tokenEndpointAuthMethod), sprintf('The token endpoint authentication method \'%s\' is not supported. Please use one of the following values: %s', $tokenEndpointAuthMethod, implode(', ', $this->getSupportedTokenEndpointAuthMethods())));

        return $this->tokenEndpointAuthMethodNames[$tokenEndpointAuthMethod];
    }

    /**
     * @return TokenEndpointAuthMethodInterface[]
     */
    public function getTokenEndpointAuthMethods(): array
    {
        return array_values($this->tokenEndpointAuthMethods);
    }

    /**
     * Find a client ID using the request
     * This interface should send the request to all its ClientManager and return null or a ClientInterface object.
     * If client is Confidential, the client credentials must be checked by by the client manager.
     *
     * @param ServerRequestInterface $request The request
     *
     * @throws OAuth2Exception Throw an exception if a client tried to authenticate against the server, but failed
     *
     * @return Client|null Return the client object.
     */
    public function findClient(ServerRequestInterface $request)
    {
        $clientId = $this->findClientInTheRequest($request, $authentication_method, $client_credentials);

        if (null !== $clientId) {
            $client = $this->clientRepository->find($clientId);
            if ($client instanceof Client && true === $this->isClientAuthenticated($request, $client, $authentication_method, $client_credentials)) {
                return $client;
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface                         $request
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface $authentication_method
     * @param mixed                                                            $client_credentials    The client credentials found in the request
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return null|ClientId
     */
    private function findClientInTheRequest(ServerRequestInterface $request, &$authentication_method, &$client_credentials = null)
    {
        $clientId = null;
        $client_credentials = null;
        foreach ($this->getTokenEndpointAuthMethods() as $method) {
            $temp = $method->findClientId($request, $client_credentials);
            if (null !== $temp) {
                if (null !== $clientId) {
                    $authentication_method = null;
                    throw new OAuth2Exception(
                        400,
                        [
                            'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                            'error_description' => 'Only one authentication method may be used to authenticate the client.',
                        ]
                    );
                } else {
                    $clientId = $temp;
                    $authentication_method = $method;
                }
            }
        }

        return $clientId;
    }

    /**
     * @param ServerRequestInterface           $request
     * @param Client                           $client
     * @param TokenEndpointAuthMethodInterface $authentication_method
     * @param $client_credentials
     *
     * @return bool
     */
    public function isClientAuthenticated(ServerRequestInterface $request, Client $client, TokenEndpointAuthMethodInterface $authentication_method, $client_credentials): bool
    {
        if (in_array($client->get('token_endpoint_auth_method'), $authentication_method->getSupportedAuthenticationMethods())) {
            if (false === $client->areClientCredentialsExpired()) {
                return $authentication_method->isClientAuthenticated($client, $client_credentials, $request);
            }
        }

        return false;
    }
}
