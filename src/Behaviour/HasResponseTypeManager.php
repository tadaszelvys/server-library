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
use OAuth2\Grant\ResponseTypeManagerInterface;

trait HasResponseTypeManager
{
    /**
     * @var \OAuth2\Grant\ResponseTypeManagerInterface|null
     */
    private $response_type_manager = null;

    /**
     * @return bool
     */
    protected function hasResponseTypeManager()
    {
        return null !== $this->response_type_manager;
    }

    /**
     * @return \OAuth2\Grant\ResponseTypeManagerInterface
     */
    protected function getResponseTypeManager()
    {
        Assertion::true($this->hasResponseTypeManager(), 'The respnse type manager is not available.');

        return $this->response_type_manager;
    }

    /**
     * @param \OAuth2\Grant\ResponseTypeManagerInterface $response_type_manager
     */
    protected function setResponseTypeManager(ResponseTypeManagerInterface $response_type_manager)
    {
        $this->response_type_manager = $response_type_manager;
    }
}
