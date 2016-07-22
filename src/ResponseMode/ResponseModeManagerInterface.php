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

interface ResponseModeManagerInterface
{
    /**
     * @param \OAuth2\ResponseMode\ResponseModeInterface $response_mode
     */
    public function addResponseMode(ResponseModeInterface $response_mode);

    /**
     * @param string $name
     *
     * @return bool
     */
    public function hasResponseMode($name);

    /**
     * @param string $name
     *
     * @throws \InvalidArgumentException
     *
     * @return \OAuth2\ResponseMode\ResponseModeInterface
     */
    public function getResponseMode($name);

    /**
     * @return string[]
     */
    public function getSupportedResponseModes();
}
