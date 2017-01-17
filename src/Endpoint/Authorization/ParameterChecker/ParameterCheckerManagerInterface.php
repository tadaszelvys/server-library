<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\ParameterChecker;

use OAuth2\Client\ClientInterface;

interface ParameterCheckerManagerInterface
{
    /**
     * @param \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerInterface $parameter_checker
     */
    public function addParameterChecker(ParameterCheckerInterface $parameter_checker);

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $parameters
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    public function checkParameters(ClientInterface $client, array &$parameters);
}
