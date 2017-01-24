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
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;

class ResponseModeParameterChecker implements ParameterCheckerInterface
{
    /**
     * @var bool
     */
    private $responseModeParameterInAuthorizationRequestAllowed;

    /**
     * ResponseModeParameterChecker constructor.
     *
     * @param bool $responseModeParameterInAuthorizationRequestAllowed
     */
    public function __construct(bool $responseModeParameterInAuthorizationRequestAllowed)
    {
        $this->responseModeParameterInAuthorizationRequestAllowed = $responseModeParameterInAuthorizationRequestAllowed;
    }

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(Client $client, array &$parameters)
    {
        if (false === array_key_exists('response_mode', $parameters)) {
            return;
        }
        Assertion::true($this->isResponseModeParameterInAuthorizationRequestAllowed(), 'The parameter \'response_mode\' is not allowed.');
    }

    /**
     * {@inheritdoc}
     */
    public function getError(): string
    {
        return OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST;
    }

    /**
     * @return bool
     */
    private function isResponseModeParameterInAuthorizationRequestAllowed(): bool
    {
        return $this->responseModeParameterInAuthorizationRequestAllowed;
    }
}
