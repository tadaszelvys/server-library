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
use OAuth2\Exception\ExceptionManagerInterface;

trait HasExceptionManager
{
    /**
     * @var \OAuth2\Exception\ExceptionManagerInterface|null
     */
    private $exception_manager = null;

    /**
     * @return bool
     */
    protected function hasExceptionManager()
    {
        return null !== $this->exception_manager;
    }

    /**
     * @return \OAuth2\Exception\ExceptionManagerInterface
     */
    protected function getExceptionManager()
    {
        Assertion::true($this->hasExceptionManager(), 'The exception manager is not available.');

        return $this->exception_manager;
    }

    /**
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    protected function setExceptionManager(ExceptionManagerInterface $exception_manager)
    {
        $this->exception_manager = $exception_manager;
    }
}
