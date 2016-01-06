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
        return $this->compareHMAC($code_challenge, $code_verifier);
    }

    /**
     * @param string $safe
     * @param string $user
     *
     * @return bool
     */
    private function compareHMAC($safe, $user)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($safe, $user);
        }
        $safeLen = strlen($safe);
        $userLen = strlen($user);

        if ($userLen !== $safeLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; $i++) {
            $result |= (ord($safe[$i]) ^ ord($user[$i]));
        }

        return $result === 0;
    }
}
