<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Response\Factory\AuthenticateResponseFactory as Base;
use OAuth2\TokenType\TokenTypeManagerInterface;

class AuthenticateResponseFactory extends Base
{
    /**
     * @var \OAuth2\TokenType\TokenTypeManagerInterface
     */
    private $token_type_manager;

    /**
     * AuthenticateResponseFactory constructor.
     *
     * @param \OAuth2\TokenType\TokenTypeManagerInterface $toket_type_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager)
    {
        $this->token_type_manager = $token_type_manager;
    }

    protected function getSchemes()
    {
        return $this->token_type_manager->getTokenTypeSchemes();
    }
}
