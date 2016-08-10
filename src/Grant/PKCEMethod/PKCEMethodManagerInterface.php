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

interface PKCEMethodManagerInterface
{
    /**
     * @param \OAuth2\Grant\PKCEMethod\PKCEMethodInterface $method
     */
    public function addPKCEMethod(PKCEMethodInterface $method);

    /**
     * @param string $code_challenge_method
     * @param string $code_challenge
     * @param string $code_verifier
     *
     * @throws \InvalidArgumentException
     */
    public function checkPKCEInput($code_challenge_method, $code_challenge, $code_verifier);
}
