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

use Psr\Http\Message\ResponseInterface;

interface ResponseModeInterface
{
    /**
     * @return string
     */
    public function getName(): string;

    /**
     * @param string $redirect_uri
     * @param array  $data
     *
     * @return ResponseInterface
     */
    public function prepareResponse(string $redirect_uri, array $data): ResponseInterface;
}
