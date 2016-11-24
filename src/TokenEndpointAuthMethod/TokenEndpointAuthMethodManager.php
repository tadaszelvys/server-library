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
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenEndpointAuthMethodManager implements TokenEndpointAuthMethodManagerInterface
{
    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var OAuth2ResponseFactoryManagerInterface
     */
    private $oauth2ResponseFactoryManager;

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
     * @param ClientRepositoryInterface $clientRepository
     * @param OAuth2ResponseFactoryManagerInterface $oauth2ResponseFactoryManager
     */
    public function __construct(ClientRepositoryInterface $clientRepository, OAuth2ResponseFactoryManagerInterface $oauth2ResponseFactoryManager)
    {
        $this->clientRepository = $clientRepository;
        $this->oauth2ResponseFactoryManager = $oauth2ResponseFactoryManager;
    }

    /**
     * {@inheritdoc}
     */
    public function addTokenEndpointAuthMethod(TokenEndpointAuthMethodInterface $tokenEndpointAuthMethod)
    {
        $this->tokenEndpointAuthMethods[] = $tokenEndpointAuthMethod;
        foreach ($tokenEndpointAuthMethod->getSupportedAuthenticationMethods() as $method_name) {
            $this->tokenEndpointAuthMethodNames[$method_name] = $tokenEndpointAuthMethod;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTokenEndpointAuthMethods(): array
    {
        return array_keys($this->tokenEndpointAuthMethodNames);
    }

    /**
     * {@inheritdoc}
     */
    public function hasTokenEndpointAuthMethod($tokenEndpointAuthMethod): bool
    {
        return array_key_exists($tokenEndpointAuthMethod, $this->tokenEndpointAuthMethodNames);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenEndpointAuthMethod($tokenEndpointAuthMethod): TokenEndpointAuthMethodInterface
    {
        Assertion::true($this->hasTokenEndpointAuthMethod($tokenEndpointAuthMethod), sprintf('The token endpoint authentication method \'%s\' is not supported. Please use one of the following values: %s', $tokenEndpointAuthMethod, implode(', ', $this->getSupportedTokenEndpointAuthMethods())));

        return $this->tokenEndpointAuthMethodNames[$tokenEndpointAuthMethod];
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenEndpointAuthMethods(): array
    {
        return array_values($this->tokenEndpointAuthMethods);
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request): Client
    {
        $id = $this->findClientInTheRequest($request, $authentication_method, $client_credentials);

        if (null !== $id) {
            $clientId = ClientId::create($id);
            $client = $this->clientRepository->find($clientId);
            if ($client instanceof Client && true === $this->isClientAuthenticated($request, $client, $authentication_method, $client_credentials)) {
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
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return null|string
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
                            'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                            'error_description' => 'Only one authentication method may be used to authenticate the client.'
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
     * @param ServerRequestInterface $request
     * @param Client $client
     * @param TokenEndpointAuthMethodInterface $authentication_method
     * @param $client_credentials
     * @return bool
     */
    public function isClientAuthenticated(ServerRequestInterface $request, Client $client, TokenEndpointAuthMethodInterface $authentication_method, $client_credentials)
    {
        if (in_array($client->get('tokenEndpointAuthMethod'), $authentication_method->getSupportedAuthenticationMethods())) {
            if (false === $client->areClientCredentialsExpired()) {
                return $authentication_method->isClientAuthenticated($client, $client_credentials, $request);
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function buildAuthenticationException(ServerRequestInterface $request): OAuth2Exception
    {
        $schemes = [];
        $message = 'Client authentication failed.';
        foreach ($this->getTokenEndpointAuthMethods() as $method) {
            $scheme = $method->getSchemesParameters();
            $schemes = array_merge($schemes, $scheme);
        }

        return new OAuth2Exception(
            401,
            [
                'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                'error_description' => $message
            ]
        );
    }
}
