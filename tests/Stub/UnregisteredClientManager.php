<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Client\UnregisteredClient;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class UnregisteredClientManager implements ClientManagerInterface
{
    use HasExceptionManager;

    /**
     * UnregisteredClientManager constructor.
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
    public function getSchemesParameters()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        $methods = $this->findClientMethods();
        $result = [];

        foreach ($methods as $method) {
            $data = $this->$method($request);
            if (null !== $data) {
                $result[] = $data;
            }
        }

        $client = $this->checkResult($result);
        if (null === $client) {
            return $client;
        }

        if (!$client instanceof UnregisteredClient) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::INVALID_CLIENT, 'The client is not an instance of UnregisteredClient.');
        }

        return $client;
    }

    /**
     * @param array $result
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface|string
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }

        $client = $this->getClient($result[0]);

        if (!$client instanceof UnregisteredClient) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Client authentication failed.', ['schemes' => $this->getSchemesParameters()]);
        }

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        /*
         * The following verification is very important!
         * If not defined, this method will always return a client, even if the client ID
         * is already used by a confidential client for example.
         */
        if ('**UNREGISTERED**--' !== substr($client_id, 0, 18)) {
            return;
        }

        $client = new UnregisteredClient();
        $client->setAllowedGrantTypes(['code', 'authorization_code']);
        $client->setPublicId($client_id);

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    protected function findClientMethods()
    {
        return [
            'findClientUsingHeader',
        ];
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    protected function findClientUsingHeader(ServerRequestInterface $request)
    {
        if (!$request->hasHeader('X-OAuth2-Unregistered-Client-ID')) {
            return;
        }

        $header = $request->getHeader('X-OAuth2-Unregistered-Client-ID');

        if (!is_array($header) || 1 !== count($header) || !is_string($header[0])) {
            return;
        }

        return $header[0];
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request, &$reason = null)
    {
        return true;
    }
}
