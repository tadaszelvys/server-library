<?php

namespace OAuth2\Test\Stub;

use OAuth2\Token\JWTAccessTokenManager as Base;
use SpomkyLabs\Service\Jose;

class JWTAccessTokenManager extends Base
{
    public function __construct()
    {
    }

    protected function getSignaturePrivateKey()
    {
        $jose = Jose::getInstance();

        return $jose->getKeysetManager()->getKeyByKid('JWK2');
    }

    protected function getSigner()
    {
        $jose = Jose::getInstance();

        return $jose->getSigner();
    }

    protected function getEncrypter()
    {
        $jose = Jose::getInstance();

        return $jose->getEncrypter();
    }

    /**
     * @return \Jose\JWKInterface
     */
    protected function getEncryptionPublicKey()
    {
        $jose = Jose::getInstance();

        return $jose->getKeysetManager()->getKeyByKid('JWK1');
    }
}
