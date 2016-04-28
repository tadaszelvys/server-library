<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect;

use OAuth2\Token\Token;

class IdToken extends Token implements IdTokenInterface
{
    /**
     * @var string
     */
    private $token_type;

    /**
     * @var null|string
     */
    private $nonce = null;

    /**
     * @var null|string
     */
    private $at_hash = null;

    /**
     * @var null|string
     */
    private $c_hash = null;

    /**
     * {@inheritdoc}
     */
    public function getTokenType()
    {
        return $this->token_type;
    }

    /**
     * {@inheritdoc}
     */
    public function setTokenType($token_type)
    {
        $this->token_type = $token_type;
    }

    /**
     * {@inheritdoc}
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * {@inheritdoc}
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenHash()
    {
        return $this->at_hash;
    }

    /**
     * {@inheritdoc}
     */
    public function setAccessTokenHash($at_hash)
    {
        $this->at_hash = $at_hash;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationCodeHash()
    {
        return $this->c_hash;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthorizationCodeHash($c_hash)
    {
        $this->c_hash = $c_hash;
    }

    /**
     * {@inheritdoc}
     */
    public function toArray()
    {
        return [
            'id_token' => $this->getToken(),
        ];
    }
}
