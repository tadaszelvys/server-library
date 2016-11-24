<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenType;

interface TokenTypeInterface2
{
    /**
     * @return string
     */
    public function getTokenTypeHint(): string;

    /**
     * @param string $token
     *
     * @return \JsonSerializable|null
     */
    public function getToken($token);
}
