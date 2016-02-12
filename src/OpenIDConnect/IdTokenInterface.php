<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use Jose\Object\JWSInterface;
use OAuth2\Token\TokenInterface;

interface IdTokenInterface extends TokenInterface
{
    /**
     * @return \Jose\Object\JWSInterface
     */
    public function getJWS();

    /**
     * @param \Jose\Object\JWSInterface $jws
     */
    public function setJWS(JWSInterface $jws);

    /**
     * The token type (bearer, mac...).
     *
     * @return string
     */
    public function getTokenType();

    /**
     * @param string $token_type
     */
    public function setTokenType($token_type);

    /**
     * @return null|string
     */
    public function getNonce();

    /**
     * @param string $nonce
     */
    public function setNonce($nonce);

    /**
     * @return null|string
     */
    public function getAccessTokenHash();

    /**
     * @param string $at_hash
     */
    public function setAccessTokenHash($at_hash);

    /**
     * @return null|string
     */
    public function getAuthorizationCodeHash();

    /**
     * @param string $c_hash
     */
    public function setAuthorizationCodeHash($c_hash);

    /**
     * @return array
     */
    public function toArray();
}
