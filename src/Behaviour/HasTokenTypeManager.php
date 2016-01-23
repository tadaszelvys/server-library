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

use OAuth2\Token\TokenTypeManagerInterface;

trait HasTokenTypeManager
{
    /**
     * @var \OAuth2\Token\TokenTypeManagerInterface
     */
    private $token_type_manager;

    /**
     * @return \OAuth2\Token\TokenTypeManagerInterface
     */
    protected function getTokenTypeManager()
    {
        return $this->token_type_manager;
    }

    /**
     * @param \OAuth2\Token\TokenTypeManagerInterface $token_type_manager
     */
    private function setTokenTypeManager(TokenTypeManagerInterface $token_type_manager)
    {
        $this->token_type_manager = $token_type_manager;
    }
}
