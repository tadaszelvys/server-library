<?php

namespace OAuth2\Test\Stub;

use OAuth2\Token\JWTAccessTokenManager as Base;

class JWTAccessTokenManager extends Base
{
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
     * @return \Jose\Object\JWKInterface
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
     * @return \Jose\Object\JWKInterface
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
