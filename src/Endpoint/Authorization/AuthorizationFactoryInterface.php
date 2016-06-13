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

use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerInterface;
use OAuth2\Grant\ResponseTypeInterface;
use OAuth2\ResponseMode\ResponseModeInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationFactoryInterface
{
    /**
     * @param \OAuth2\Grant\ResponseTypeInterface $response_type
     */
    public function addResponseType(ResponseTypeInterface $response_type);

    /**
     * @param \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerInterface $parameter_checker
     */
    public function addParameterChecker(ParameterCheckerInterface $parameter_checker);
    
    /**
     * @return string[]
     */
    public function getResponseTypesSupported();

    /**
     * @param \OAuth2\ResponseMode\ResponseModeInterface $response_mode
     */
    public function addResponseMode(ResponseModeInterface $response_mode);

    /**
     * @return string[]
     */
    public function getResponseModesSupported();

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    public function createAuthorizationFromRequest(ServerRequestInterface $request);
}
