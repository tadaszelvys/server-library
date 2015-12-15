<?php

namespace OAuth2\Behaviour;

use OAuth2\Util\JWTEncrypter;

trait HasJWTEncrypter
{
    /**
     * @var \OAuth2\Util\JWTEncrypter
     */
    private $jwt_encrypter;

    /**
     * @return \OAuth2\Util\JWTEncrypter
     */
    protected function getJWTEncrypter()
    {
        return $this->jwt_encrypter;
    }

    /**
     * @param \OAuth2\Util\JWTEncrypter jwt_encrypter
     */
    private function setJWTEncrypter(JWTEncrypter $jwt_encrypter)
    {
        $this->jwt_encrypter = $jwt_encrypter;
    }
}
