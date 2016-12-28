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

use Http\Factory\Diactoros\ServerRequestFactory;
use Interop\Http\Factory\ServerRequestFactoryInterface;

trait ServerRequestFactoryTrait
{
    /**
     * @var null|ServerRequestFactoryInterface
     */
    private $serverRequestFactory = null;

    /**
     * @return ServerRequestFactoryInterface
     */
    public function getServerRequestFactory(): ServerRequestFactoryInterface
    {
        if (null === $this->serverRequestFactory) {
            $this->serverRequestFactory = new ServerRequestFactory();
        }

        return $this->serverRequestFactory;
    }
}
