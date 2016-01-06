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

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class JWTClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;
    use HasJWTLoader;

    /**
     * JWTClientManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                       $jwt_loader
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(JWTLoader $jwt_loader, ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        $this->setJWTLoader($jwt_loader);
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        return [];
    }

    /**
     * @return string[]
     */
    protected function findClientCredentialsMethods()
    {
        $methods = [
            'findCredentialsFromClientAssertion',
        ];

        return $methods;
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request)
    {
        $methods = $this->findClientCredentialsMethods();
        $assertions = [];

        foreach ($methods as $method) {
            $data = $this->$method($request);
            if (null !== ($data)) {
                $assertions[] = $data;
            }
        }

        $client = $this->checkResult($assertions);
        if (null === $client) {
            return $client;
        }

        $this->getJWTLoader()->verifySignature($assertions[0], $client);

        return $client;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\Object\JWSInterface
     */
    protected function findCredentialsFromClientAssertion(ServerRequestInterface $request)
    {
        $client_assertion_type = RequestBody::getParameter($request, 'client_assertion_type');

        //We verify the client assertion type in the request
        if ('urn:ietf:params:oauth:client-assertion-type:jwt-bearer' !== $client_assertion_type) {
            return;
        }

        $client_assertion = RequestBody::getParameter($request, 'client_assertion');
        //We verify the client assertion exists
        if (null === $client_assertion) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_assertion" is missing.');
        }

        //We load the assertion
        $jwt = $this->getJWTLoader()->load($client_assertion);

        return $jwt;
    }

    /**
     * @param \Jose\Object\JWEInterface[] $result
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Client\JWTClientInterface
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }
        if (!$result[0]->hasClaim('sub')) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "sub" is missing.');
        }

        $client = $this->getClient($result[0]->getClaim('sub'));

        if (!$client instanceof JWTClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Client authentication failed.', ['schemes' => $this->getSchemesParameters()]);
        }

        return $client;
    }
}
