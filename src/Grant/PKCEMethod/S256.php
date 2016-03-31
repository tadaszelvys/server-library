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

use Base64Url\Base64Url;

final class S256 implements PKCEMethodInterface
{
    /**
     * {@inheritdoc}
     */
    public function getMethodName()
    {
        return 'S256';
    }

    /**
     * {@inheritdoc}
     */
    public function isChallengeVerified($code_verifier, $code_challenge)
    {
        return hash_equals($code_challenge, Base64Url::encode(hash('sha256', $code_verifier, true)));
    }
}
