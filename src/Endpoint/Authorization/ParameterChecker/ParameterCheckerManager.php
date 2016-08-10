<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;

final class ParameterCheckerManager implements ParameterCheckerManagerInterface
{
    use HasScopeManager;
    use HasExceptionManager;

    private $parameter_checkers = [];

    /**
     * ParameterCheckerManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function addParameterChecker(ParameterCheckerInterface $parameter_checker)
    {
        $this->parameter_checkers[] = $parameter_checker;
    }

    /**
     * {@inheritdoc}
     */
    public function checkParameters(ClientInterface $client, array &$parameters)
    {
        foreach ($this->parameter_checkers as $parameter_checker) {
            try {
                $parameter_checker->checkerParameter($client, $parameters);
            } catch (\InvalidArgumentException $e) {
                throw $this->getExceptionManager()->getBadRequestException($parameter_checker->getError(), $e->getMessage());
            }
        }
    }
}
