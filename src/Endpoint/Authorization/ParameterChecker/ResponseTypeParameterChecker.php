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

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;

class ResponseTypeParameterChecker implements ParameterCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        /*
         * @see http://tools.ietf.org/html/rfc6749#section-3.1.1
         */
        Assertion::keyExists($parameters, 'response_type', 'The parameter "response_type" is mandatory.');
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return ExceptionManagerInterface::ERROR_INVALID_REQUEST;
    }
}
