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

interface PKCEMethodInterface
{
    /**
     * @return string
     */
    public function getMethodName(): string;

    /**
     * @param string $codeVerifier
     * @param string $codeChallenge
     *
     * @return bool
     */
    public function isChallengeVerified(string $codeVerifier, string $codeChallenge): bool;
}
