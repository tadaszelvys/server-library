<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use OAuth2\Exception\ExceptionManagerInterface;

trait HasExceptionManager
{
    /**
     * @var \OAuth2\Exception\ExceptionManagerInterface
     */
    private $exception_manager;

    /**
     * @return \OAuth2\Exception\ExceptionManagerInterface
     */
    protected function getExceptionManager()
    {
        return $this->exception_manager;
    }

    /**
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    private function setExceptionManager(ExceptionManagerInterface $exception_manager)
    {
        $this->exception_manager = $exception_manager;
    }
}
