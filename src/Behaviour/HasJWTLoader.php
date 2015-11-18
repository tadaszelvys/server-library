<?php

namespace OAuth2\Behaviour;

use OAuth2\Util\JWTLoader;

trait HasJWTLoader
{
    /**
     * @var \OAuth2\Util\JWTLoader
     */
    protected $jwt_loader;

    /**
     * @return \OAuth2\Util\JWTLoader
     */
    public function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \OAuth2\Util\JWTLoader $jwt_loader
     *
     * @return self
     */
    public function setJWTLoader(JWTLoader $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;

        return $this;
    }
}
