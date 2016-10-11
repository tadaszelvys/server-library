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
use OAuth2\ResponseMode\ResponseModeManagerInterface;

trait HasResponseModeManager
{
    /**
     * @var \OAuth2\ResponseMode\ResponseModeManagerInterface|null
     */
    private $response_mode_manager = null;

    /**
     * @return bool
     */
    protected function hasResponseModeManager()
    {
        return null !== $this->response_mode_manager;
    }

    /**
     * @return \OAuth2\ResponseMode\ResponseModeManagerInterface
     */
    protected function getResponseModeManager()
    {
        Assertion::true($this->hasResponseModeManager(), 'The response mode manager is not available.');

        return $this->response_mode_manager;
    }

    /**
     * @param \OAuth2\ResponseMode\ResponseModeManagerInterface $response_mode_manager
     */
    protected function setResponseModeManager(ResponseModeManagerInterface $response_mode_manager)
    {
        $this->response_mode_manager = $response_mode_manager;
    }
}
