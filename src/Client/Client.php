<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use OAuth2\ResourceOwner\ResourceOwner;

class Client extends ResourceOwner implements ClientInterface
{
    /**
     * @var string[]
     */
    protected $grant_types = [];

    /**
     * {@inheritdoc}
     */
    public function isAllowedGrantType($grant_type)
    {
        return in_array($grant_type, $this->grant_types);
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedGrantTypes()
    {
        return $this->grant_types;
    }

    /**
     * {@inheritdoc}
     */
    public function addAllowedGrantType($grant_type)
    {
        if (!$this->isAllowedGrantType($grant_type)) {
            $this->grant_types[] = $grant_type;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function setAllowedGrantTypes(array $grant_types)
    {
        $this->grant_types = $grant_types;
    }

    /**
     * {@inheritdoc}
     */
    public function removeAllowedGrantType($grant_type)
    {
        $key = array_search($grant_type, $this->grant_types);
        if (false !== $key) {
            unset($this->grant_types[$key]);
        }
    }
}
