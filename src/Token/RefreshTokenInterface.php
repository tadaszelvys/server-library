<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

interface RefreshTokenInterface extends TokenInterface
{
    /**
     * Is the refresh token marked as used.
     *
     * @return bool
     */
    public function isUsed();

    /**
     * @param bool $used
     *
     * @return self
     */
    public function setUsed($used);
}
