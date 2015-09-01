<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\JWTClientManager as Base;
use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;
use SpomkyLabs\Service\Jose;

class JWTClientManager extends Base
{
    private $clients = [];

    public function __construct()
    {
        $jwk1 = new JWK([
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ]);
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk1);
        $jwk_set->addKey($jwk2);

        $jwt1 = new JWTClient();
        $jwt1->setAllowedSignatureAlgorithms(['HS512'])
             ->setPublicKeySet($jwk_set)
             ->setRedirectUris(['http://example.com/test?good=false'])
             ->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'])
             ->setPublicId('jwt1');

        $jwt2 = new JWTClient();
        $jwt2->setAllowedSignatureAlgorithms(['HS512'])
             ->setPublicKeySet($jwk_set)
             ->setRedirectUris([])
             ->setAllowedGrantTypes(['authorization_code'])
             ->setPublicId('jwt2');

        $this->clients['jwt1'] = $jwt1;
        $this->clients['jwt2'] = $jwt2;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return isset($this->clients[$client_id]) ? $this->clients[$client_id] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getPrivateKeySet()
    {
        $jwk1 = new JWK([
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ]);
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk1);
        $jwk_set->addKey($jwk2);

        return $jwk_set;
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedEncryptionAlgorithms()
    {
        return ['A256KW', 'A256CBC-HS512'];
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWTLoader()
    {
        $jose = Jose::getInstance();

        return $jose->getLoader();
    }
}
