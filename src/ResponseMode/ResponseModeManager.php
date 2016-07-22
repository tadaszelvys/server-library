<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseMode;

use Assert\Assertion;

final class ResponseModeManager implements ResponseModeManagerInterface
{
    /**
     * @var \OAuth2\ResponseMode\ResponseModeInterface[]
     */
    private $response_modes = [];

    /**
     * {@inheritdoc}
     */
    public function addResponseMode(ResponseModeInterface $response_mode)
    {
        $this->response_modes[$response_mode->getName()] = $response_mode;
    }

    /**
     * {@inheritdoc}
     */
    public function hasResponseMode($name)
    {
        return array_key_exists($name, $this->response_modes);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode($name)
    {
        Assertion::true($this->hasResponseMode($name), sprintf('The response mode with name "%s" is not supported.', $name));

        return $this->response_modes[$name];
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedResponseModes()
    {
        return array_keys($this->response_modes);
    }
}
