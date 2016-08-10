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

use OAuth2\ResponseMode\ResponseModeManagerInterface;

trait HasResponseModeManager
{
    /**
     * @var \OAuth2\ResponseMode\ResponseModeManagerInterface
     */
    private $response_mode_manager;

    /**
     * @return \OAuth2\ResponseMode\ResponseModeManagerInterface
     */
    private function getResponseModeManager()
    {
        return $this->response_mode_manager;
    }

    /**
     * @param \OAuth2\ResponseMode\ResponseModeManagerInterface $response_mode_manager
     */
    private function setResponseModeManager(ResponseModeManagerInterface $response_mode_manager)
    {
        $this->response_mode_manager = $response_mode_manager;
    }
}
