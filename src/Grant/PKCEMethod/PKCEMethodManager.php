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
        Assertion::false(array_key_exists($method->getMethodName(), $this->pkce_methods), sprintf('The method "%s" already exists.', $method->getMethodName()));
        $this->pkce_methods[$method->getMethodName()] = $method;
    }

    /**
     * {@inheritdoc}
     */
    public function checkPKCEInput($code_challenge_method, $code_challenge, $code_verifier)
    {
        Assertion::true($this->hasPKCEMethod($code_challenge_method), sprintf('Unsupported code challenge method "%s".', $code_challenge_method));
        $method = $this->getPKCEMethod($code_challenge_method);
        Assertion::notNull($code_verifier, 'The parameter "code_verifier" is required.');
        Assertion::true($method->isChallengeVerified($code_verifier, $code_challenge), 'Invalid parameter "code_verifier".');
    }

    /**
     * {@inheritdoc}
     */
    public function hasPKCEMethod($method)
    {
        return array_key_exists($method, $this->pkce_methods);
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethod($method)
    {
        return $this->pkce_methods[$method];
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethods()
    {
        return array_values($this->pkce_methods);
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethodNames()
    {
        return array_keys($this->pkce_methods);
    }
}
