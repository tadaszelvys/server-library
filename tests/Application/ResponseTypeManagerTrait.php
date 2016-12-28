<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Application;

use OAuth2\Grant\ResponseTypeManager;
use OAuth2\Grant\ResponseTypeManagerInterface;

trait ResponseTypeManagerTrait
{
    /**
     * @var null|ResponseTypeManagerInterface
     */
    private $responseTypeManager = null;

    /**
     * @return ResponseTypeManagerInterface
     */
    public function getResponseTypeManager(): ResponseTypeManagerInterface
    {
        if (null === $this->responseTypeManager) {
            $this->responseTypeManager = new ResponseTypeManager();
        }

        return $this->responseTypeManager;
    }
}
