<?php

namespace OAuth2\Behaviour;

use OAuth2\Token\AccessTokenTypeInterface;

trait HasAccessTokenType
{
    /**
     * @var \OAuth2\Token\AccessTokenTypeInterface
     */
    protected $access_token_type;

    /**
     * @return \OAuth2\Token\AccessTokenTypeInterface
     */
    public function getAccessTokenType()
    {
        return $this->access_token_type;
    }

    /**
     * @param \OAuth2\Token\AccessTokenTypeInterface $access_token_type
     *
     * @return self
     */
    public function setAccessTokenType(AccessTokenTypeInterface $access_token_type)
    {
        $this->access_token_type = $access_token_type;

        return $this;
    }
}
