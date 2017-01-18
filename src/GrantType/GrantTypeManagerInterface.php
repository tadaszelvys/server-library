<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\GrantType;

interface GrantTypeManagerInterface
{
    /**
     * @param GrantTypeInterface $grant_type
     *
     * @return GrantTypeManagerInterface
     */
    public function addGrantType(GrantTypeInterface $grant_type): GrantTypeManagerInterface;

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
     * @return GrantTypeInterface
     */
    public function getGrantType($name);

    /**
     * @return string[]
     */
    public function getSupportedGrantTypes();
}
