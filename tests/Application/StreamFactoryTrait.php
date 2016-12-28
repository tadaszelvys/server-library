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

use Http\Factory\Diactoros\StreamFactory;
use Interop\Http\Factory\StreamFactoryInterface;

trait StreamFactoryTrait
{
    /**
     * @var null|StreamFactoryInterface
     */
    private $streamFactory = null;

    /**
     * @return StreamFactoryInterface
     */
    public function getStreamFactory(): StreamFactoryInterface
    {
        if (null === $this->streamFactory) {
            $this->streamFactory = new StreamFactory();
        }

        return $this->streamFactory;
    }
}
