<?php

namespace OAuth2\Test\Stub;

use OAuth2\Token\JWTAccessTokenManager as Base;
use SpomkyLabs\Service\Jose;

class JWTAccessTokenManager extends Base
{
    public function getLoader()
    {
        $jose = Jose::getInstance();

        return $jose->getLoader();
    }

    public function getSigner()
    {
        $jose = Jose::getInstance();

        return $jose->getSigner();
    }

    public function getEncrypter()
    {
        $jose = Jose::getInstance();

        return $jose->getEncrypter();
    }

    public function getKeyManager()
    {
        $jose = Jose::getInstance();

        return $jose->getKeyManager();
    }

    public function getKeySetManager()
    {
        $jose = Jose::getInstance();

        return $jose->getKeysetManager();
    }

    public function getSignaturePrivateKey()
    {
        $jose = Jose::getInstance();

        return $jose->getKeysetManager()->getKeyByKid('JWK2')->getValues();
    }

    public function getSignaturePublicKey()
    {
        $jose = Jose::getInstance();

        return $jose->getKeysetManager()->getKeyByKid('JWK2')->getValues();
    }

    /**
     * @return \Jose\JWKInterface
     */
    public function getEncryptionPublicKey()
    {
        $jose = Jose::getInstance();

        return $jose->getKeysetManager()->getKeyByKid('JWK1')->getValues();
    }

    /**
     * @return \Jose\JWKInterface
     */
    public function getEncryptionPrivateKey()
    {
        $jose = Jose::getInstance();

        return $jose->getKeysetManager()->getKeyByKid('JWK1')->getValues();
    }
}
