<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

interface ResponseTypeManagerInterface
{
    /**
     * @param \OAuth2\Grant\ResponseTypeInterface $response_type
     */
    public function addResponseType(ResponseTypeInterface $response_type);

    /**
     * @param string $name
     *
     * @return bool
     */
    public function hasResponseType($name);

    /**
     * @param string $names
     *
     * @throws \InvalidArgumentException
     *
     * @return \OAuth2\Grant\ResponseTypeInterface[]
     */
    public function getResponseTypes($names);

    /**
     * @return string[]
     */
    public function getSupportedResponseTypes();

    /**
     * @param string $response_type
     *
     * @return bool
     */
    public function isResponseTypeSupported($response_type);
}
