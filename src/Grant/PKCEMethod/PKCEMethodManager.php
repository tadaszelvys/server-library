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

final class PKCEMethodManager implements PKCEMethodManagerInterface
{
    /**
     * @var \OAuth2\Grant\PKCEMethod\PKCEMethodInterface[]
     */
    private $pkce_methods = [];

    /**
     * {@inheritdoc}
     */
    public function addPKCEMethod(PKCEMethodInterface $method)
    {
        if (!array_key_exists($method->getMethodName(), $this->pkce_methods)) {
            $this->pkce_methods[$method->getMethodName()] = $method;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkPKCEInput($code_challenge_method, $code_challenge, $code_verifier)
    {
        Assertion::true($this->hasPKCEMethods($code_challenge_method), sprintf('Unsupported code challenge method "%s".', $code_challenge_method));
        $method = $this->getPKCEMethod($code_challenge_method);
        Assertion::notNull($code_verifier, 'The parameter "code_verifier" is required.');
        Assertion::true($method->isChallengeVerified($code_verifier, $code_challenge), 'Invalid parameter "code_verifier".');
    }

    /**
     * @param string $method
     *
     * @return bool
     */
    private function hasPKCEMethods($method)
    {
        return array_key_exists($method, $this->pkce_methods);
    }

    /**
     * @param string $method
     *
     * @return \OAuth2\Grant\PKCEMethod\PKCEMethodInterface
     */
    private function getPKCEMethod($method)
    {
        return $this->pkce_methods[$method];
    }
}
