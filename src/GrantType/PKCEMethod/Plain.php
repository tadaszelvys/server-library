<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\GrantType\PKCEMethod;

class Plain implements PKCEMethodInterface
{
    /**
     * {@inheritdoc}
     */
    public function getMethodName(): string
    {
        return 'plain';
    }

    /**
     * {@inheritdoc}
     */
    public function isChallengeVerified(string $codeVerifier, string $codeChallenge): bool
    {
        return hash_equals($codeChallenge, $codeVerifier);
    }
}
