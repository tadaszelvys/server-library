<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use Security\DefuseGenerator;

abstract class SimpleStringAccessTokenManager extends AccessTokenManager
{
    use HasExceptionManager;

    /**
     * {@inheritdoc}
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null)
    {
        $length = $this->getAccessTokenLength();
        $charset = $this->getConfiguration()->get('simple_string_access_token_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $token = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($token) || strlen($token) !== $length) {
            throw $this->createException('An error has occurred during the creation of the token.');
        }

        $access_token->setToken($token);
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getAccessTokenLength()
    {
        $min_length = $this->getConfiguration()->get('simple_string_access_token_min_length', 20);
        $max_length = $this->getConfiguration()->get('simple_string_access_token_max_length', 30);
        srand();

        return rand(min($min_length, $max_length), max($min_length, $max_length));
    }

    /**
     * @param string $message
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    private function createException($message)
    {
        return $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, $message);
    }
}
