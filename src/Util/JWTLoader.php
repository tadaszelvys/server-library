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
use Jose\Checker\CheckerManagerInterface;
use Jose\Factory\DecrypterFactory;
use Jose\Factory\VerifierFactory;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;

final class JWTLoader
{
    /**
     * @var \Jose\Checker\CheckerManagerInterface
     */
    private $checker_manager;

    /**
     * @var \Jose\DecrypterInterface|null
     */
    private $decrypter = null;

    /**
     * @var \Jose\VerifierInterface
     */
    private $verifier;

    /**
     * @var string[]
     */
    private $supported_signature_algorithms;

    /**
     * @var string[]
     */
    private $supported_key_encryption_algorithms = [];

    /**
     * @var string[]
     */
    private $supported_content_encryption_algorithms = [];

    /**
     * JWTLoader constructor.
     *
     * @param \Jose\Checker\CheckerManagerInterface $checker_manager
     * @param string[]                              $supported_signature_algorithms
     */
    public function __construct(CheckerManagerInterface $checker_manager, array $supported_signature_algorithms)
    {
        $this->checker_manager = $checker_manager;
        $this->verifier = VerifierFactory::createVerifier($supported_signature_algorithms);

        $this->supported_signature_algorithms = $supported_signature_algorithms;
    }

    /**
     * @param string[] $supported_key_encryption_algorithms
     * @param string[] $supported_content_encryption_algorithms
     * @param string[] $compression_methods
     */
    public function enableEncryptionSupport(array $supported_key_encryption_algorithms,
                                            array $supported_content_encryption_algorithms,
                                            array $compression_methods = ['DEF', 'ZLIB', 'GZ']
    ) {
        Assertion::notEmpty($supported_key_encryption_algorithms, 'At least one key encryption algorithm must be set.');
        Assertion::notEmpty($supported_content_encryption_algorithms, 'At least one content encryption algorithm must be set.');

        $this->decrypter = DecrypterFactory::createDecrypter(array_merge($supported_key_encryption_algorithms, $supported_content_encryption_algorithms), $compression_methods);
        $this->supported_key_encryption_algorithms = $supported_key_encryption_algorithms;
        $this->supported_content_encryption_algorithms = $supported_content_encryption_algorithms;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->supported_signature_algorithms;
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return $this->supported_key_encryption_algorithms;
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return $this->supported_content_encryption_algorithms;
    }

    /**
     * @param string                            $assertion
     * @param array                             $allowed_key_encryption_algorithms
     * @param array                             $allowed_content_encryption_algorithms
     * @param \Jose\Object\JWKSetInterface|null $encryption_key_set
     * @param bool                              $is_encryption_required
     *
     * @return \Jose\Object\JWSInterface
     */
    public function load($assertion, array $allowed_key_encryption_algorithms = [], array $allowed_content_encryption_algorithms = [], JWKSetInterface $encryption_key_set = null, $is_encryption_required = false)
    {
        Assertion::string($assertion);
        Assertion::boolean($is_encryption_required);
        $jwt = Loader::load($assertion);
        if ($jwt instanceof JWEInterface) {
            Assertion::true($this->isEncryptionSupportEnabled(), 'Encryption support is not enabled.');
            $key_encryption_algorithms = array_intersect($allowed_key_encryption_algorithms, $this->supported_key_encryption_algorithms);
            $content_encryption_algorithms = array_intersect($allowed_content_encryption_algorithms, $this->supported_content_encryption_algorithms);
            Assertion::inArray($jwt->getSharedProtectedHeader('alg'), $key_encryption_algorithms, sprintf('The key encryption algorithm "%s" is not allowed.', $jwt->getSharedProtectedHeader('alg')));
            Assertion::inArray($jwt->getSharedProtectedHeader('enc'), $content_encryption_algorithms, sprintf('The content encryption algorithm "%s" is not allowed or not supported.', $jwt->getSharedProtectedHeader('enc')));
            $jwt = $this->decryptAssertion($jwt, $encryption_key_set);
        } elseif (true === $is_encryption_required) {
            throw new \InvalidArgumentException('The assertion must be encrypted.');
        }

        return $jwt;
    }

    /**
     * @return bool
     */
    private function isEncryptionSupportEnabled()
    {
        return null !== $this->decrypter;
    }

    /**
     * @param \Jose\Object\JWEInterface    $jwe
     * @param \Jose\Object\JWKSetInterface $encryption_key_set
     *
     * @return \Jose\Object\JWEInterface|\Jose\Object\JWSInterface
     */
    private function decryptAssertion(JWEInterface $jwe, JWKSetInterface $encryption_key_set)
    {
        $this->decrypter->decryptUsingKeySet($jwe, $encryption_key_set);

        $jws = Loader::load($jwe->getPayload());
        Assertion::isInstanceOf($jws, JWSInterface::class, 'The encrypted assertion does not contain a JWS.');

        return $jws;
    }

    /**
     * @param \Jose\Object\JWSInterface    $jws
     * @param \Jose\Object\JWKSetInterface $signature_key_set
     * @param array                        $allowed_signature_algorithms
     */
    public function verifySignature(JWSInterface $jws, JWKSetInterface $signature_key_set, array $allowed_signature_algorithms)
    {
        $algorithms = array_intersect(
            $allowed_signature_algorithms,
            $this->supported_signature_algorithms
        );
        Assertion::inArray($jws->getSignature(0)->getProtectedHeader('alg'), $algorithms, sprintf('The signature algorithm "%s" is not supported or not allowed.', $jws->getSignature(0)->getProtectedHeader('alg')));

        $this->verifier->verifyWithKeySet($jws, $signature_key_set, null, $index);
        $this->checker_manager->checkJWS($jws, $index);
    }
}
