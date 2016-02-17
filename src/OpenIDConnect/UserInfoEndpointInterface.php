<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface UserInfoEndpointInterface
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request  The request
     * @param \Psr\Http\Message\ResponseInterface      $response The response
     */
    public function getUserInfo(ServerRequestInterface $request, ResponseInterface &$response);

    /**
     * @return string[]
     */
    public function getSignatureAlgorithms();

    /**
     * @return string[]
     */
    public function getKeyEncryptionAlgorithms();

    /**
     * @return string[]
     */
    public function getContentEncryptionAlgorithms();
}
