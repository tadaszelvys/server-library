<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Util;

use Jose\DecrypterInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWSInterface;
use Jose\LoaderInterface;
use Jose\VerifierInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\JWTClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;

final class JWTLoader
{
    use HasExceptionManager;

    /**
     * @var bool
     */
    protected $is_encryption_required = false;

    /**
     * @var \Jose\LoaderInterface
     */
    protected $loader;

    /**
     * @var \Jose\DecrypterInterface
     */
    protected $decrypter;

    /**
     * @var \Jose\VerifierInterface
     */
    protected $verifier;

    /**
     * @var string[]
     */
    protected $allowed_encryption_algorithms = [];

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    protected $key_set;

    /**
     * JWTLoader constructor.
     *
     * @param \Jose\LoaderInterface                       $loader
     * @param \Jose\VerifierInterface                     $verifier
     * @param \Jose\DecrypterInterface                    $decrypter
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     * @param string[]                                    $allowed_encryption_algorithms
     * @param array                                       $key_set
     * @param bool                                        $is_encryption_required
     */
    public function __construct(
        LoaderInterface $loader,
        VerifierInterface $verifier,
        DecrypterInterface $decrypter,
        ExceptionManagerInterface $exception_manager,
        array $allowed_encryption_algorithms = [],
        array $key_set = [],
        $is_encryption_required = false
    )
    {
        $this->loader = $loader;
        $this->verifier = $verifier;
        $this->decrypter = $decrypter;
        $this->allowed_encryption_algorithms = $allowed_encryption_algorithms;
        $this->key_set = new JWKSet($key_set);
        $this->is_encryption_required = $is_encryption_required;
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param $assertion
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface
     */
    public function load($assertion)
    {
        //We load the assertion
        $jwt = $this->loadAssertion($assertion);
        if ($jwt instanceof JWEInterface) {
            $jwt = $this->decryptAssertion($jwt);
        } elseif (true === $this->is_encryption_required) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The assertion must be encrypted.');
        }

        return $jwt;
    }

    /**
     * @param string $assertion
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\Object\JWSInterface|\Jose\Object\JWEInterface
     */
    protected function loadAssertion($assertion)
    {
        $jwt = $this->loader->load($assertion);
        if (!$jwt instanceof JWEInterface && !$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The assertion does not contain a single JWS or a single JWE.');
        }

        return $jwt;
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\Object\JWSInterface
     */
    protected function decryptAssertion(JWEInterface $jwe)
    {
        if (!in_array($jwe->getHeader('alg'), $this->allowed_encryption_algorithms) || !in_array($jwe->getHeader('enc'), $this->allowed_encryption_algorithms)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Algorithm not allowed. Authorized algorithms: %s.', json_encode($this->allowed_encryption_algorithms)));
        }
        $this->decrypter->decrypt($jwe, $this->key_set);
        if (null === $jwe->getPayload()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to decrypt the payload. Please verify keys used for encryption.');
        }
        $jws = $this->loader->load($jwe->getPayload());
        if (!$jws instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The encrypted assertion does not contain a single JWS.');
        }

        return $jws;
    }

    /**
     * @param \Jose\Object\JWSInterface         $jws
     * @param \OAuth2\Client\JWTClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function verifySignature(JWSInterface $jws, JWTClientInterface $client)
    {
        if (!in_array($jws->getHeader('alg'), $client->getAllowedSignatureAlgorithms())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Algorithm not allowed. Authorized algorithms: %s.', json_encode($client->getAllowedSignatureAlgorithms())));
        }

        if (false === $this->verifier->verify($jws, $this->key_set)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Invalid signature.');
        }
    }
}
