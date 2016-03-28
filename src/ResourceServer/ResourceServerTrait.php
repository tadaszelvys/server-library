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
    protected $key_encryption_algorithm;

    /**
     * @var string[]
     */
    protected $content_encryption_algorithm;

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
    public function getPublicKeyEncryptionKey()
    {
        return $this->public_key_encryption_keyset;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyEncryptionAlgorithm()
    {
        return $this->key_encryption_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getContentEncryptionAlgorithm()
    {
        return $this->content_encryption_algorithm;
    }
}
