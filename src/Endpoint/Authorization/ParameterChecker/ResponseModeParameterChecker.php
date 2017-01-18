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

class ResponseModeParameterChecker implements ParameterCheckerInterface
{
    /**
     * @var bool
     */
    private $response_mode_parameter_in_authorization_request_allowed = false;

    /**
     * ResponseModeParameterChecker constructor.
     *
     * @param bool $response_mode_parameter_in_authorization_request_allowed
     */
    public function __construct($response_mode_parameter_in_authorization_request_allowed)
    {
        Assertion::boolean($response_mode_parameter_in_authorization_request_allowed);
        $this->response_mode_parameter_in_authorization_request_allowed = $response_mode_parameter_in_authorization_request_allowed;
    }

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        if (false === array_key_exists('response_mode', $parameters)) {
            return;
        }
        Assertion::true($this->isResponseModeParameterInAuthorizationRequestAllowed(), 'The parameter \'response_mode\' is not allowed.');
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST;
    }

    /**
     * {@inheritdoc}
     */
    private function isResponseModeParameterInAuthorizationRequestAllowed()
    {
        return $this->response_mode_parameter_in_authorization_request_allowed;
    }
}
