<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use OAuth2\Endpoint\Authorization\Extension\AuthorizationEndpointExtensionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationEndpointInterface
{
    /**
     * @param \OAuth2\Endpoint\Authorization\Extension\AuthorizationEndpointExtensionInterface $extension
     */
    public function addExtension(AuthorizationEndpointExtensionInterface $extension);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function authorize(ServerRequestInterface $request);
}
