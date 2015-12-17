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

final class Plain implements PKCEMethodInterface
{
    /**
     * {@inheritdoc}
     */
    public function getMethodName()
    {
        return 'plain';
    }

    /**
     * {@inheritdoc}
     */
    public function isChallengeVerified($code_verifier, $code_challenge)
    {
        return hash_equals($code_challenge, $code_verifier);
    }
}
