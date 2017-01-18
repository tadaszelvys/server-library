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

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;

/**
 * Class StateParameterChecker.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
 */
class NonceParameterChecker implements ParameterCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        if (false === strpos($parameters['response_type'], 'id_token')) {
            return;
        }
        Assertion::true(array_key_exists('nonce', $parameters), 'The parameter \'nonce\' is mandatory.');
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST;
    }
}
