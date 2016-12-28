<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Application;

use Jose\Checker\CheckerManager;
use Jose\Decrypter;
use Jose\Encrypter;
use Jose\JWTCreator;
use Jose\JWTLoader;
use Jose\Signer;
use Jose\Verifier;

trait JwtTrait
{
    /**
     * @var null|JWTCreator
     */
    private $jwtCreator = null;

    /**
     * @var null|JWTLoader
     */
    private $jwtLoader = null;

    /**
     * @var null|Signer
     */
    private $jwtSigner = null;

    /**
     * @var null|Verifier
     */
    private $jwtVerifier = null;

    /**
     * @var null|Encrypter
     */
    private $jwtEncrypter = null;

    /**
     * @var null|Decrypter
     */
    private $jwtDecrypter = null;

    /**
     * @var null|CheckerManager
     */
    private $jwtCheckerManager = null;

    /**
     * @return JWTCreator
     */
    public function getJwtCreator(): JWTCreator
    {
        if (null === $this->jwtCreator) {
            $this->jwtCreator = new JWTCreator(
                $this->getJwtSigner()
            );
            $this->jwtCreator->enableEncryptionSupport(
                $this->getJwtEncrypter()
            );
        }

        return $this->jwtCreator;
    }

    /**
     * @return JWTLoader
     */
    public function getJwtLoader(): JWTLoader
    {
        if (null === $this->jwtLoader) {
            $this->jwtLoader = new JWTLoader(
                $this->getJwtChecker(),
                $this->getJwtVerifier()
            );

            $this->jwtLoader->enableDecryptionSupport(
                $this->getJwtDecrypter()
            );
        }

        return $this->jwtLoader;
    }

    private function getJwtChecker(): CheckerManager
    {
        if (null === $this->jwtCheckerManager) {
            $this->jwtCheckerManager = new CheckerManager();
        }

        return $this->jwtCheckerManager;
    }

    private function getJwtSigner(): Signer
    {
        if (null === $this->jwtSigner) {
            $this->jwtSigner = new Signer([
                'HS256',
                'RS256',
                'ES256',
            ]);
        }

        return $this->jwtSigner;
    }

    private function getJwtVerifier(): Verifier
    {
        if (null === $this->jwtVerifier) {
            $this->jwtVerifier = new Verifier([
                'HS256',
                'RS256',
                'ES256',
            ]);
        }

        return $this->jwtVerifier;
    }

    private function getJwtEncrypter(): Encrypter
    {
        if (null === $this->jwtEncrypter) {
            $this->jwtEncrypter = new Encrypter(
                ['RSA-OAEP', 'RSA-OAEP-256'],
                ['A256GCM', 'A256CBC-HS512'],
                ['DEF']
            );
        }

        return $this->jwtEncrypter;
    }

    private function getJwtDecrypter(): Decrypter
    {
        if (null === $this->jwtDecrypter) {
            $this->jwtDecrypter = new Decrypter(
                ['RSA-OAEP', 'RSA-OAEP-256'],
                ['A256GCM', 'A256CBC-HS512'],
                ['DEF']
            );
        }

        return $this->jwtDecrypter;
    }
}
