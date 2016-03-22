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

use Assert\Assertion;
use Jose\Object\JWKSetInterface;
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
     * @var bool
     */
    private $encryption_required = false;

    /**
     * @var \Jose\Object\JWKSetInterface|null
     */
    private $key_encryption_key_set = null;

    /**
     * @var string[]
     */
    private $allowed_key_encryption_algorithms = [];

    /**
     * @var string[]
     */
    private $allowed_content_encryption_algorithms = [];

    /**
     * JWTClientManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                      $loader
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(
        JWTLoader $loader,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setJWTLoader($loader);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param bool                         $encryption_required
     * @param string[]                     $allowed_key_encryption_algorithms
     * @param string[]                     $allowed_content_encryption_algorithms
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function enableEncryptedAssertions($encryption_required,
                                              array $allowed_key_encryption_algorithms,
                                              array $allowed_content_encryption_algorithms,
                                              JWKSetInterface $key_encryption_key_set)
    {
        Assertion::boolean($encryption_required);
        Assertion::notEmpty($allowed_key_encryption_algorithms);
        Assertion::notEmpty($allowed_content_encryption_algorithms);

        $this->encryption_required = $encryption_required;
        $this->allowed_key_encryption_algorithms = $allowed_key_encryption_algorithms;
        $this->allowed_content_encryption_algorithms = $allowed_content_encryption_algorithms;
        $this->key_encryption_key_set = $key_encryption_key_set;
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
        if (!$client instanceof SignatureCapabilitiesInterface) {
            return false;
        }

        try {
            $this->getJWTLoader()->verifySignature(
                $client_credentials,
                $client->getSignaturePublicKeySet(),
                $client->getAllowedSignatureAlgorithms()
            );

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
        try {
            $jwt = $this->getJWTLoader()->load(
                $client_assertion,
                $this->allowed_key_encryption_algorithms,
                $this->allowed_content_encryption_algorithms,
                $this->key_encryption_key_set,
                $this->encryption_required
            );
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        return $jwt;
    }

    /**
     * @param \Jose\Object\JWEInterface[] $result
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Client\SignatureCapabilitiesInterface
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

        if (!$client instanceof SignatureCapabilitiesInterface) {
            return;
        }

        return $client;
    }
}
