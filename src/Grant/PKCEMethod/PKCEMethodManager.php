<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant\PKCEMethod;

use Assert\Assertion;

class PKCEMethodManager implements PKCEMethodManagerInterface
{
    /**
     * @var \OAuth2\Grant\PKCEMethod\PKCEMethodInterface[]
     */
    private $pkceMethods = [];

    /**
     * {@inheritdoc}
     */
    public function addPKCEMethod(PKCEMethodInterface $method): PKCEMethodManagerInterface
    {
        $this->pkceMethods[$method->getMethodName()] = $method;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function checkPKCEInput(string $codeChallengeMethod, string $codeChallenge, string $codeVerifier)
    {
        Assertion::true($this->hasPKCEMethod($codeChallengeMethod), sprintf('Unsupported code challenge method \'%s\'.', $codeChallengeMethod));
        $method = $this->getPKCEMethod($codeChallengeMethod);
        Assertion::notNull($codeVerifier, 'The parameter \'code_verifier\' is required.');
        Assertion::true($method->isChallengeVerified($codeVerifier, $codeChallenge), 'Invalid parameter \'code_verifier\'.');
    }

    /**
     * {@inheritdoc}
     */
    public function hasPKCEMethod(string $method): bool
    {
        return array_key_exists($method, $this->pkceMethods);
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethod(string $method): PKCEMethodInterface
    {
        return $this->pkceMethods[$method];
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethods(): array
    {
        return array_values($this->pkceMethods);
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethodNames(): array
    {
        return array_keys($this->pkceMethods);
    }
}
