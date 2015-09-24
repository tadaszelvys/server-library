<?php

namespace OAuth2\Behaviour;

use OAuth2\Util\JWTFactory;

trait HasJWTFactory
{
    /**
     * @var \OAuth2\Util\JWTFactory
     */
    protected $jwt_factory;

    /**
     * @return \OAuth2\Util\JWTFactory
     */
    public function getJWTFactory()
    {
        return $this->jwt_factory;
    }

    /**
     * @param \OAuth2\Util\JWTFactory $jwt_factory
     *
     * @return self
     */
    public function setJWTFactory(JWTFactory $jwt_factory)
    {
        $this->jwt_factory = $jwt_factory;

        return $this;
    }
}
