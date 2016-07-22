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

interface GrantTypeManagerInterface
{
    /**
     * @param \OAuth2\Grant\GrantTypeInterface $grant_type
     */
    public function addGrantType(GrantTypeInterface $grant_type);

    /**
     * @param string $name
     *
     * @return bool
     */
    public function hasGrantType($name);

    /**
     * @param string $name
     *
     * @throws \InvalidArgumentException
     *
     * @return \OAuth2\Grant\GrantTypeInterface
     */
    public function getGrantType($name);

    /**
     * @return string[]
     */
    public function getSupportedGrantTypes();
}
