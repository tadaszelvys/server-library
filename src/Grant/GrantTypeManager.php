<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use Assert\Assertion;

class GrantTypeManager implements GrantTypeManagerInterface
{
    /**
     * @var \OAuth2\Grant\GrantTypeInterface[]
     */
    private $grant_types = [];

    /**
     * {@inheritdoc}
     */
    public function addGrantType(GrantTypeInterface $grant_type): GrantTypeManagerInterface
    {
        $this->grant_types[$grant_type->getGrantType()] = $grant_type;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function hasGrantType($name)
    {
        return array_key_exists($name, $this->grant_types);
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType($names)
    {
        Assertion::true($this->hasGrantType($names), sprintf('The grant type \'%s\' is not supported.', $names));

        return $this->grant_types[$names];
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedGrantTypes()
    {
        return array_keys($this->grant_types);
    }
}
