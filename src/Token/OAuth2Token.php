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

class OAuth2Token extends Token implements OAuth2TokenInterface
{
    /**
     * @var array
     */
    protected $metadatas = [];

    /**
     * @var array
     */
    protected $scope = [];

    /**
     * @var string
     */
    protected $client_public_id;

    /**
     * @var string
     */
    protected $resource_owner_public_id;

    /**
     * {@inheritdoc}
     */
    public function getClientPublicId()
    {
        return $this->client_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setClientPublicId($client_public_id)
    {
        $this->client_public_id = $client_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function hasScope($scope)
    {
        return in_array($scope, $this->getScope());
    }

    /**
     * {@inheritdoc}
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * {@inheritdoc}
     */
    public function setScope(array $scope)
    {
        $this->scope = $scope;
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerPublicId()
    {
        return $this->resource_owner_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setResourceOwnerPublicId($resource_owner_public_id)
    {
        $this->resource_owner_public_id = $resource_owner_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getMetadatas()
    {
        return $this->metadatas;
    }

    /**
     * {@inheritdoc}
     */
    public function setMetadatas(array $metadatas)
    {
        $this->metadatas = $metadatas;
    }

    /**
     * {@inheritdoc}
     */
    public function setMetadata($key, $value)
    {
        Assertion::string($key);
        $this->metadatas[$key] = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function getMetadata($key)
    {
        Assertion::true($this->hasMetadata($key), sprintf('Metadata with key "%s" does not exist.', $key));

        return $this->metadatas[$key];
    }

    /**
     * {@inheritdoc}
     */
    public function hasMetadata($key)
    {
        Assertion::string($key);

        return array_key_exists($key, $this->metadatas);
    }

    /**
     * {@inheritdoc}
     */
    public function unsetMetadata($key)
    {
        Assertion::string($key);
        if (array_key_exists($key, $this->metadatas)) {
            unset($this->metadatas[$key]);
        }
    }
}
