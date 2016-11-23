<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use Assert\Assertion;
use OAuth2\TokenType\TokenTypeManagerInterface;

trait HasTokenTypeManager
{
    /**
     * @var \OAuth2\TokenType\TokenTypeManagerInterface|null
     */
    private $token_type_manager = null;

    /**
     * @return bool
     */
    protected function hasTokenTypeManager()
    {
        return null !== $this->token_type_manager;
    }

    /**
     * @return \OAuth2\TokenType\TokenTypeManagerInterface
     */
    protected function getTokenTypeManager()
    {
        Assertion::true($this->hasTokenTypeManager(), 'The token type manager is not available.');

        return $this->token_type_manager;
    }

    /**
     * @param \OAuth2\TokenType\TokenTypeManagerInterface $token_type_manager
     */
    protected function setTokenTypeManager(TokenTypeManagerInterface $token_type_manager)
    {
        $this->token_type_manager = $token_type_manager;
    }
}
