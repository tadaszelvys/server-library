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
use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface;

trait HasParameterCheckerManager
{
    /**
     * @var \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface|null
     */
    private $parameter_checker_manager = null;

    /**
     * @return bool
     */
    protected function hasParameterCheckerManager()
    {
        return null !== $this->parameter_checker_manager;
    }

    /**
     * @return \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface
     */
    protected function getParameterCheckerManager()
    {
        Assertion::true($this->hasParameterCheckerManager(), 'The parameter checker manager is not available.');

        return $this->parameter_checker_manager;
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface $parameter_checker_manager
     */
    protected function setParameterCheckerManager(ParameterCheckerManagerInterface $parameter_checker_manager)
    {
        $this->parameter_checker_manager = $parameter_checker_manager;
    }
}
