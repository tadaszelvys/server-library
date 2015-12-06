<?php

namespace OAuth2\Test\Stub;

use Jose\JWKManager;
use Jose\JWKSetManager;
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
        return new JWKManager();
    }

    public function getKeySetManager()
    {
        return new JWKSetManager();
    }

    public function getSignaturePrivateKey()
    {
        return [
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ];
    }

    public function getSignaturePublicKey()
    {
        return [
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ];
    }

    /**
     * @return \Jose\JWKInterface
     */
    public function getEncryptionPublicKey()
    {
        return [
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ];
    }

    /**
     * @return \Jose\JWKInterface
     */
    public function getEncryptionPrivateKey()
    {
        return [
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ];
    }
}
