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

use OAuth2\Grant\GrantTypeManagerInterface;

trait HasGrantTypeManager
{
    /**
     * @var \OAuth2\Grant\GrantTypeManagerInterface
     */
    private $response_type_manager;

    /**
     * @return \OAuth2\Grant\GrantTypeManagerInterface
     */
    public function getGrantTypeManager()
    {
        return $this->response_type_manager;
    }

    /**
     * @param \OAuth2\Grant\GrantTypeManagerInterface $response_type_manager
     */
    public function setGrantTypeManager(GrantTypeManagerInterface $response_type_manager)
    {
        $this->response_type_manager = $response_type_manager;
    }
}
