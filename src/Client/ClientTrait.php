<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

trait ClientTrait
{
    /**
     * @var string[]
     */
    protected $grant_types = [];

    /**
     * @var string[]
     */
    protected $response_types = [];

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
    public function isAllowedResponseType($response_type)
    {
        return in_array($response_type, $this->response_types);
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedResponseTypes()
    {
        return $this->response_types;
    }
}
