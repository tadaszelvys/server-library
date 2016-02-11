<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Util;

use Assert\Assertion;
use Jose\ClaimChecker\ClaimCheckerManagerInterface;
use Jose\DecrypterInterface;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\VerifierInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientWithSignatureCapabilitiesInterface;
use OAuth2\Exception\ExceptionManagerInterface;

final class JWTLoader
{
    use HasExceptionManager;

    /**
     * @var \Jose\ClaimChecker\ClaimCheckerManagerInterface
     */
    private $claim_checker_manager;

    /**
     * @var bool
     */
    private $is_encryption_required = false;

    /**
     * @var \Jose\DecrypterInterface
     */
    private $decrypter;

    /**
     * @var \Jose\VerifierInterface
     */
    private $verifier;

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $key_set;

    /**
     * JWTLoader constructor.
     *
     * @param \Jose\ClaimChecker\ClaimCheckerManagerInterface $claim_checker_manager
     * @param \Jose\VerifierInterface                         $verifier
     * @param \Jose\DecrypterInterface                        $decrypter
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     * @param \Jose\Object\JWKSetInterface                    $key_set
     * @param bool                                            $is_encryption_required
     */
    public function __construct(
        ClaimCheckerManagerInterface $claim_checker_manager,
        VerifierInterface $verifier,
        DecrypterInterface $decrypter,
        ExceptionManagerInterface $exception_manager,
        JWKSetInterface $key_set,
        $is_encryption_required = false
    ) {
        $this->claim_checker_manager = $claim_checker_manager;
        $this->verifier = $verifier;
        $this->decrypter = $decrypter;
        $this->key_set = $key_set;
        $this->is_encryption_required = $is_encryption_required;
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param $assertion
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\Object\JWSInterface
     */
    public function load($assertion)
    {
        $jwt = $this->loadAssertion($assertion);
        if ($jwt instanceof JWEInterface) {
            Assertion::same(1, $jwt->countRecipients(), 'The assertion does not contain a single JWS or a single JWE.');
            $this->claim_checker_manager->checkClaims($jwt);
            $jwt = $this->decryptAssertion($jwt);
        } elseif (true === $this->is_encryption_required) {
            throw new \InvalidArgumentException('The assertion must be encrypted.');
        }
        Assertion::same(1, $jwt->countSignatures(), 'The assertion does not contain a single JWS or a single JWE.');
        $this->claim_checker_manager->checkClaims($jwt);

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
        $jwt = Loader::load($assertion);
        if (!$jwt instanceof JWEInterface && !$jwt instanceof JWSInterface) {
            throw new \InvalidArgumentException('The assertion does not contain a single JWS or a single JWE.');
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
        if (false === $this->decrypter->decryptUsingKeySet($jwe, $this->key_set)) {
            throw new \InvalidArgumentException('Unable to decrypt the payload. Please verify keys used for encryption.');
        }
        $jws = Loader::load($jwe->getPayload());
        if (!$jws instanceof JWSInterface) {
            throw new \InvalidArgumentException('The encrypted assertion does not contain a single JWS.');
        }

        return $jws;
    }

    /**
     * @param \Jose\Object\JWSInterface                               $jws
     * @param \OAuth2\Client\ClientWithSignatureCapabilitiesInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function verifySignature(JWSInterface $jws, ClientWithSignatureCapabilitiesInterface $client)
    {
        if (0 === $jws->countSignatures()) {
            throw new \InvalidArgumentException('The JWS does not contain any signature.');
        }

        if (false === $signature_id = $this->verifier->verifyWithKeySet($jws, $client->getSignaturePublicKeySet())) {
            throw new \InvalidArgumentException('Invalid signature.');
        }
        $signature = $jws->getSignature($signature_id);
        $headers = $signature->getAllHeaders();
        if (!in_array($headers['alg'], $client->getAllowedSignatureAlgorithms())) {
            throw new \InvalidArgumentException(sprintf('Algorithm not allowed. Authorized algorithms: %s.', json_encode($client->getAllowedSignatureAlgorithms())));
        }
    }
}
