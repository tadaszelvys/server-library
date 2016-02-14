<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResourceServer;

use Assert\Assertion;
use Jose\Object\JWKSetInterface;
use OAuth2\Client\Client;

/**
 * Class ResourceServer.
 */
trait ResourceServerTrait
{
    /**
     * @var string
     */
    protected $server_name;

    /**
     * @var string[]
     */
    protected $supported_key_encryption_algorithms;

    /**
     * @var string[]
     */
    protected $supported_content_encryption_algorithms;

    /**
     * @var null|\Jose\Object\JWKSetInterface
     */
    protected $public_key_encryption_keyset;

    /**
     * {@inheritdoc}
     */
    public function getServerName()
    {
        return $this->server_name;
    }

    /**
     * {@inheritdoc}
     */
    public function isAllowedGrantType($grant_type)
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedGrantTypes()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'resource_server';
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKeyEncryptionKey()
    {
        return $this->public_key_encryption_keyset;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return $this->supported_key_encryption_algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return $this->supported_content_encryption_algorithms;
    }
}
