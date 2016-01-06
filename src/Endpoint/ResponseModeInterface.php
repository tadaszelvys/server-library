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

interface ResponseModeInterface
{
    /**
     * @return string
     */
    public function getName();

    /**
     * @param string                              $redirect_uri
     * @param array                               $data
     * @param \Psr\Http\Message\ResponseInterface $response
     */
    public function prepareResponse($redirect_uri, array $data, ResponseInterface &$response);
}
