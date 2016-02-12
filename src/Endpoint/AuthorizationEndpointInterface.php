<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use Psr\Http\Message\ResponseInterface;

interface AuthorizationEndpointInterface
{
    /**
     * @param \OAuth2\Endpoint\Authorization      $authorization
     * @param \Psr\Http\Message\ResponseInterface $response
     */
    public function authorize(Authorization $authorization, ResponseInterface &$response);

    /**
     * @return string[]
     */
    public function getResponseTypesSupported();

    /**
     * @return string[]
     */
    public function getResponseModesSupported();
}
