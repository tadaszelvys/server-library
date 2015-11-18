<?php

namespace OAuth2\Behaviour;

use OAuth2\Token\AccessTokenManagerInterface;

trait HasAccessTokenManager
{
    /**
     * @var \OAuth2\Token\AccessTokenManagerInterface
     */
    protected $access_token_manager;

    /**
     * @return \OAuth2\Token\AccessTokenManagerInterface
     */
    public function getAccessTokenManager()
    {
        return $this->access_token_manager;
    }

    /**
     * @param \OAuth2\Token\AccessTokenManagerInterface $access_token_manager
     *
     * @return self
     */
    public function setAccessTokenManager(AccessTokenManagerInterface $access_token_manager)
    {
        $this->access_token_manager = $access_token_manager;

        return $this;
    }
}
