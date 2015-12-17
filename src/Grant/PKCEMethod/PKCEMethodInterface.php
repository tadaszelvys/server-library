<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant\PKCEMethod;

interface PKCEMethodInterface
{
    /**
     * @return string
     */
    public function getMethodName();

    /**
     * @param string $code_verifier
     * @param string $code_challenge
     *
     * @return mixed
     */
    public function isChallengeVerified($code_verifier, $code_challenge);
}
