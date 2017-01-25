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

namespace OAuth2\TokenTypeHint;

use OAuth2\Model\Token\Token;
use OAuth2\Model\Token\TokenId;

interface TokenTypeHintInterface
{
    /**
     * @return string
     */
    public function hint(): string;

    /**
     * @param string $token
     *
     * @return null|Token
     */
    public function find(string $token);

    /**
     * @param TokenId $tokenId
     */
    public function revoke(TokenId $tokenId);

    /**
     * @param TokenId $tokenId
     *
     * @return array
     */
    public function introspect(TokenId $tokenId): array;
}
