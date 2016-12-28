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

use Http\Factory\Diactoros\ResponseFactory;
use Interop\Http\Factory\ResponseFactoryInterface;

trait ResponseFactoryTrait
{
    /**
     * @var null|ResponseFactoryInterface
     */
    private $responseFactory = null;

    /**
     * @return ResponseFactoryInterface
     */
    public function getResponseFactory(): ResponseFactoryInterface
    {
        if (null === $this->responseFactory) {
            $this->responseFactory = new ResponseFactory();
        }

        return $this->responseFactory;
    }
}
