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

use OAuth2\Grant\ResponseTypeManagerInterface;

trait HasResponseTypeManager
{
    /**
     * @var \OAuth2\Grant\ResponseTypeManagerInterface
     */
    private $response_type_manager;

    /**
     * @return \OAuth2\Grant\ResponseTypeManagerInterface
     */
    public function getResponseTypeManager()
    {
        return $this->response_type_manager;
    }

    /**
     * @param \OAuth2\Grant\ResponseTypeManagerInterface $response_type_manager
     */
    public function setResponseTypeManager(ResponseTypeManagerInterface $response_type_manager)
    {
        $this->response_type_manager = $response_type_manager;
    }
}
