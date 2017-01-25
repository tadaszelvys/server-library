<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use OAuth2\Model\Client\Client;

interface ParameterCheckerManagerInterface
{
    /**
     * @param ParameterCheckerInterface $parameter_checker
     *
     * @return ParameterCheckerManagerInterface
     */
    public function addParameterChecker(ParameterCheckerInterface $parameter_checker): ParameterCheckerManagerInterface;

    /**
     * @param Client $client
     * @param array  $parameters
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    public function checkParameters(Client $client, array &$parameters);
}
