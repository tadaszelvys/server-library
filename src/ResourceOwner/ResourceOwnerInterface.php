<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResourceOwner;

interface ResourceOwnerInterface
{
    /**
     * Get resource owner identifier. The ID is a string that represents the resource owner and is unique to the authorization server.
     *
     * @return string ID of the resource owner
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.2
     */
    public function getPublicId();

    /**
     * @param string $key
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    public function get($key);

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has($key);
}
