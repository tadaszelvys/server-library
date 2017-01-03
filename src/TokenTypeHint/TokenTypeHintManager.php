<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
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
    public function addTokenTypeHint(TokenTypeHintInterface $tokenTypeHint)
    {
        $this->tokenTypeHints[$tokenTypeHint->getTokenTypeHint()] = $tokenTypeHint;
    }
}
