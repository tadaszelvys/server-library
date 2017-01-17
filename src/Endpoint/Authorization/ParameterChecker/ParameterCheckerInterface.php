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

interface ParameterCheckerInterface
{
    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $parameters
     *
     * @throws \InvalidArgumentException
     */
    public function checkerParameter(ClientInterface $client, array &$parameters);

    /**
     * @return string
     */
    public function getError();
}
