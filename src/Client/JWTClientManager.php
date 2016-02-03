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

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Exception\BaseException;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class JWTClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasJWTLoader;

    /**
     * JWTClientManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                       $jwt_loader
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     */
    public function __construct(JWTLoader $jwt_loader, ExceptionManagerInterface $exception_manager)
    {
        $this->setJWTLoader($jwt_loader);
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
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        $methods = $this->findClientCredentialsMethods();
        $assertions = [];

        foreach ($methods as $method) {
            $data = $this->$method($request);
            if (null !== ($data)) {
                $assertions[] = $data;
            }
        }

        if (null === $client = $this->checkResult($assertions)) {
            return;
        }
        $client_credentials = $assertions[0];

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request, &$reason = null)
    {
        if (!$client instanceof ClientWithSignatureCapabilitiesInterface) {
            return false;
        }

        try {
            $this->getJWTLoader()->verifySignature($client_credentials, $client);

            return true;
        } catch (BaseException $e) {
            $reason = $e->getDescription();

            return false;
        } catch (\Exception $e) {
            $reason = $e->getMessage();

            return false;
        }
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
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_assertion" is missing.');
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
     * @return \OAuth2\Client\ClientWithEncryptionCapabilitiesInterface
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }
        if (!$result[0]->hasClaim('sub')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "sub" is missing.');
        }

        $client = $this->getClient($result[0]->getClaim('sub'));

        if (!$client instanceof ClientWithSignatureCapabilitiesInterface) {
            return;
        }

        return $client;
    }
}
