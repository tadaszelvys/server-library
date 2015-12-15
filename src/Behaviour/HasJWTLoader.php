<?php

namespace OAuth2\Behaviour;

use OAuth2\Util\JWTLoader;

trait HasJWTLoader
{
    /**
     * @var \OAuth2\Util\JWTLoader
     */
    private $jwt_loader;

    /**
     * @return \OAuth2\Util\JWTLoader
     */
    protected function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \OAuth2\Util\JWTLoader $jwt_loader
     */
    private function setJWTLoader(JWTLoader $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;
    }
}
