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

interface TokenTypeHintManagerInterface
{
    /**
     * @return TokenTypeHintInterface[]
     */
    public function getTokenTypeHints(): array;

    /**
     * @param TokenTypeHintInterface $tokenTypeHint
     *
     * @return TokenTypeHintManagerInterface
     */
    public function addTokenTypeHint(TokenTypeHintInterface $tokenTypeHint): TokenTypeHintManagerInterface;
}