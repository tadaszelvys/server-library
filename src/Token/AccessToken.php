<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

class AccessToken extends Token implements AccessTokenInterface
{
    /**
     * @var string
     */
    protected $token_type;

    /**
     * @var null|string
     */
    protected $refresh_token;

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
    public function getRefreshToken()
    {
        return $this->refresh_token;
    }

    /**
     * {@inheritdoc}
     */
    public function setRefreshToken($refresh_token)
    {
        $this->refresh_token = $refresh_token;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * {@inheritdoc}
     */
    public function toArray()
    {
        $values = array_merge([
                'access_token' => $this->getToken(),
                'token_type'   => $this->getTokenType(),
                'expires_in'   => $this->getExpiresIn(),
                'scope'        => count($this->getScope()) ? implode(' ', $this->getScope()) : null,
            ],
            $this->getParameters()
        );

        if (empty($values['scope'])) {
            unset($values['scope']);
        }
        if (!empty($this->getRefreshToken())) {
            $values['refresh_token'] = $this->getRefreshToken();
        }

        return $values;
    }
}
