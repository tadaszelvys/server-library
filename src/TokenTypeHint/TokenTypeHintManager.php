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

final class TokenTypeHintManager implements TokenTypeHintManagerInterface
{
    /**
     * @var TokenTypeHintInterface[]
     */
    private $tokenTypeHints = [];

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHints(): array
    {
        return $this->tokenTypeHints;
    }

    /**
     * {@inheritdoc}
     */
    public function addTokenTypeHint(TokenTypeHintInterface $tokenTypeHint): TokenTypeHintManagerInterface
    {
        $this->tokenTypeHints[$tokenTypeHint->getTokenTypeHint()] = $tokenTypeHint;

        return $this;
    }
}