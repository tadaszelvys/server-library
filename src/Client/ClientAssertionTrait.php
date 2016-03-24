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
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

trait ClientAssertionTrait
{
    /**
     * @return \OAuth2\Util\JWTLoader
     */
    abstract protected function getJWTLoader();

    /**
     * @return \OAuth2\Exception\ExceptionManagerInterface
     */
    abstract protected function getExceptionManager();

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
    private function verifyClientAssertion(ClientInterface $client, $client_credentials, &$reason)
    {
        try {
            $this->getJWTLoader()->verifySignature(
                $client_credentials,
                $client->getSignaturePublicKeySet(),
                $client->getAllowedSignatureAlgorithms()
            );
        } catch (\Exception $e) {
            $reason = $e->getMessage();

            return false;
        }

        return true;
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
            return;
        }

        if (false === $jwt->hasClaim('sub')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The assertion does not contain the "sub" claim.');
        }

        return [
            'client_id'          => $jwt->getClaim('sub'),
            'client_credentials' => $jwt,
        ];
    }
}
