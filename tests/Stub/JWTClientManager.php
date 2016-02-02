<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Jose\Object\JWKSet;
use OAuth2\Client\JWTClientManager as Base;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\JWTLoader;

class JWTClientManager extends Base
{
    /**
     * @var \OAuth2\Client\JWTClient[]
     */
    private $clients = [];

    /**
     * JWTClientManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                       $jwt_loader
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     */
    public function __construct(JWTLoader $jwt_loader, ExceptionManagerInterface $exception_manager)
    {
        parent::__construct($jwt_loader, $exception_manager);

        $keys = ['keys' => [[
                'kid' => 'JWK1',
                'use' => 'enc',
                'kty' => 'oct',
                'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
            ],
            [
                'kid' => 'JWK2',
                'use' => 'sig',
                'kty' => 'oct',
                'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
            ],
        ]];

        $jwt1 = new JWTClient();
        $jwt1->setAllowedSignatureAlgorithms(['HS512']);
        $jwt1->setSignaturePublicKeySet(new JWKSet($keys));
        $jwt1->setRedirectUris(['http://example.com/test?good=false']);
        $jwt1->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'id_token', 'none', 'refresh_token', 'code', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $jwt1->setPublicId('jwt1');

        $jwt2 = new JWTClient();
        $jwt2->setAllowedSignatureAlgorithms(['HS512']);
        $jwt2->setSignaturePublicKeySet(new JWKSet($keys));
        $jwt2->setRedirectUris([]);
        $jwt2->setAllowedGrantTypes(['authorization_code']);
        $jwt2->setPublicId('jwt2');

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
}
