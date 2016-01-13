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

use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessTokenTypeManagerInterface;
use OAuth2\Token\IdToken;
use OAuth2\Token\IdTokenInterface;
use OAuth2\Token\IdTokenManager as Base;
use OAuth2\Util\JWTSigner;

class IdTokenManager extends Base
{
    /**
     * @var \OAuth2\Token\IdTokenInterface[]
     */
    private $id_tokens = [];

    /**
     * IdTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTSigner                        $jwt_signer
     * @param \OAuth2\Exception\ExceptionManagerInterface   $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface  $configuration
     * @param \OAuth2\Token\AccessTokenTypeManagerInterface $access_token_type_manager
     */
    public function __construct(JWTSigner $jwt_signer, ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration, AccessTokenTypeManagerInterface $access_token_type_manager)
    {
        parent::__construct($jwt_signer, $exception_manager, $configuration);

        $abcd = new IdToken();
        $abcd->setExpiresAt(time() + 3600);
        $abcd->setResourceOwnerPublicId('bar');
        $abcd->setScope([]);
        $abcd->setClientPublicId('bar');
        $abcd->setToken('ABCD');

        $efgh = new IdToken();
        $efgh->setExpiresAt(time() + 3600);
        $efgh->setResourceOwnerPublicId('foo');
        $efgh->setScope([]);
        $efgh->setClientPublicId('foo');
        $efgh->setToken('EFGH');

        $this->saveIdToken($abcd);
        $this->saveIdToken($efgh);
    }

    /**
     * {@inheritdoc}
     */
    protected function saveIdToken(IdTokenInterface $id_token)
    {
        $this->id_tokens[$id_token->getToken()] = $id_token;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdToken($id_token)
    {
        return array_key_exists($id_token, $this->id_tokens) ? $this->id_tokens[$id_token] : null;
    }
}
