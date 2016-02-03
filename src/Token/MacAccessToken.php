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

use Assert\Assertion;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Security\DefuseGenerator;

class MacAccessToken implements TokenTypeInterface
{
    use HasExceptionManager;

    /**
     * @var string
     */
    private $mac_key_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/';

    /**
     * @var string
     */
    private $mac_algorithm = 'hmac-sha-256';

    /**
     * @var int
     */
    private $mac_key_min_length = 20;

    /**
     * @var int
     */
    private $mac_key_max_length = 50;

    /**
     * AuthCodeManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeName()
    {
        return 'MAC';
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeInformation()
    {
        return [
            'token_type'    => $this->getTokenTypeName(),
            'mac_key'       => $this->generateMacKey(),
            'mac_algorithm' => $this->getMacAlgorithm(),
        ];
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function generateMacKey()
    {
        $length = $this->getMacKeyLength();
        $charset = $this->getMacKeyCharset();
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
        $min_length = $this->getMacKeyMinLength();
        $max_length = $this->getMacKeyMaxLength();
        srand();

        return rand($min_length, $max_length);
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

    /**
     * @return string
     */
    public function getMacKeyCharset()
    {
        return $this->mac_key_charset;
    }

    /**
     * @param string $mac_key_charset
     */
    public function setMacKeyCharset($mac_key_charset)
    {
        Assertion::string($mac_key_charset);
        $this->$mac_key_charset = $mac_key_charset;
    }

    /**
     * @return int
     */
    public function getMacKeyMinLength()
    {
        return $this->mac_key_min_length;
    }

    /**
     * @param int $mac_key_min_length
     */
    public function setMacKeyMinLength($mac_key_min_length)
    {
        Assertion::integer($mac_key_min_length);
        Assertion::lessThan($mac_key_min_length, $this->getMacKeyMaxLength());
        $this->mac_key_min_length = $mac_key_min_length;
    }

    /**
     * @return int
     */
    public function getMacKeyMaxLength()
    {
        return $this->mac_key_max_length;
    }

    /**
     * @param int $mac_key_max_length
     */
    public function setMacKeyMaxLength($mac_key_max_length)
    {
        Assertion::integer($mac_key_max_length);
        Assertion::greaterThan($mac_key_max_length, $this->getMacKeyMinLength());
        $this->mac_key_max_length = $mac_key_max_length;
    }

    /**
     * @return string
     */
    public function getMacAlgorithm()
    {
        return $this->mac_algorithm;
    }

    /**
     * @param int $mac_algorithm
     */
    public function setMacAlgorithm($mac_algorithm)
    {
        Assertion::string($mac_algorithm);
        $this->mac_algorithm = $mac_algorithm;
    }
}
