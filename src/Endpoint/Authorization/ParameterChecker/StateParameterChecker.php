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

/**
 * Class StateParameterChecker.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
 */
final class StateParameterChecker implements ParameterCheckerInterface
{
    /**
     * @var bool
     */
    private $state_parameter_enforced = false;

    /**
     * StateParameterChecker constructor.
     *
     * @param bool $state_parameter_enforced
     */
    public function __construct($state_parameter_enforced)
    {
        Assertion::boolean($state_parameter_enforced);
        $this->state_parameter_enforced = $state_parameter_enforced;
    }

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        if (false === $this->state_parameter_enforced) {
            return;
        }
        Assertion::true(array_key_exists('state', $parameters), 'The parameter "state" is mandatory.');
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return ExceptionManagerInterface::INVALID_REQUEST;
    }
}
