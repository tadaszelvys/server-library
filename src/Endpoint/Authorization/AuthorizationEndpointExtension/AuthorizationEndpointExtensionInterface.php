<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\AuthorizationEndpointExtension;

use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationEndpointExtensionInterface
{
    /**
     * @param array                                                 $response_parameters
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization);
}
