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

use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationFactoryInterface
{
    /**
     * @return bool
     */
    public function isResponseModeParameterSupported();

    public function enableResponseModeParameterSupport();

    public function disableResponseModeParameterSupport();

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    public function createAuthorizationFromRequest(ServerRequestInterface $request);

    /**
     * @param array                                 $params
     * @param \OAuth2\Grant\ResponseTypeInterface[] $types
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return \OAuth2\ResponseMode\ResponseModeInterface
     */
    public function getResponseMode(array $params, array $types);

    /**
     * @param array $params
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return \OAuth2\Grant\ResponseTypeInterface[]
     */
    public function getResponseTypes(array $params);
}
