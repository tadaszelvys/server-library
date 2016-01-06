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

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Security\DefuseGenerator;

class MacAccessToken implements AccessTokenTypeInterface
{
    use HasConfiguration;
    use HasExceptionManager;

    /**
     * AuthCodeManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

    /**
     * {@inheritdoc}
     */
    public function updateAccessToken(AccessTokenInterface &$token)
    {
        $token->setTokenType($this->getTokenTypeName());
        $token->setParameter('mac_key', $this->generateMacKey());
        $token->setParameter('mac_algorithm', $this->getConfiguration()->get('mac_algorithm', 'hmac-sha-256'));
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeName()
    {
        return 'MAC';
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function generateMacKey()
    {
        $length = $this->getMacKeyLength();
        $charset = $this->getConfiguration()->get('mac_key_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $mac_key = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($mac_key) || strlen($mac_key) !== $length) {
            throw $this->createException('An error has occurred during the creation of the authorization code.');
        }

        return $mac_key;
    }

    /**
     * @return int
     */
    private function getMacKeyLength()
    {
        $min_length = $this->getConfiguration()->get('mac_key_min_length', 20);
        $max_length = $this->getConfiguration()->get('mac_key_max_length', 30);
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
