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
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;

class DisplayParameterChecker implements ParameterCheckerInterface
{
    const DISPLAY_PAGE = 'page';
    const DISPLAY_POPUP = 'popup';
    const DISPLAY_TOUCH = 'touch';
    const DISPLAY_WAP = 'wap';

    /**
     * {@inheritdoc}
     */
    public function checkerParameter(ClientInterface $client, array &$parameters)
    {
        if (!array_key_exists('display', $parameters)) {
            return;
        }
        Assertion::true(in_array($parameters['display'], $this->getAllowedDisplayValues()), sprintf('Invalid parameter \'display\'. Allowed values are %s', implode(', ', $this->getAllowedDisplayValues())));
    }

    /**
     * {@inheritdoc}
     */
    public function getError()
    {
        return OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST;
    }

    /**
     * @return string[]
     */
    private function getAllowedDisplayValues()
    {
        return [
            self::DISPLAY_PAGE,
            self::DISPLAY_POPUP,
            self::DISPLAY_TOUCH,
            self::DISPLAY_WAP,
        ];
    }
}
