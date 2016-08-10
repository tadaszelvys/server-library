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

use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface;

trait HasParameterCheckerManager
{
    /**
     * @var \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface
     */
    private $parameter_checker_manager;

    /**
     * @return \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface
     */
    private function getParameterCheckerManager()
    {
        return $this->parameter_checker_manager;
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface $parameter_checker_manager
     */
    private function setParameterCheckerManager(ParameterCheckerManagerInterface $parameter_checker_manager)
    {
        $this->parameter_checker_manager = $parameter_checker_manager;
    }
}
