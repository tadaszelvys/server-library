<?php

namespace OAuth2\Behaviour;

use OAuth2\Token\AccessTokenTypeInterface;
use OAuth2\Token\AccessTokenTypeManagerInterface;

trait HasAccessTokenTypeManager
{
    /**
     * @var \OAuth2\Token\AccessTokenTypeManagerInterface
     */
    protected $access_token_type_manager;

    /**
     * @return \OAuth2\Token\AccessTokenTypeManagerInterface
     */
    public function getAccessTokenTypeManager()
    {
        return $this->access_token_type_manager;
    }

    /**
     * @param \OAuth2\Token\AccessTokenTypeManagerInterface $access_token_type_manager
     *
     * @return self
     */
    public function setAccessTokenTypeManager(AccessTokenTypeManagerInterface $access_token_type_manager)
    {
        $this->access_token_type_manager = $access_token_type_manager;

        return $this;
    }
}
