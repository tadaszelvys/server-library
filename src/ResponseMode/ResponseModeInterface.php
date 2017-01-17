<?php

declare(strict_types=1);

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
use Psr\Http\Message\UriInterface;

interface ResponseModeInterface
{
    /**
     * @return string
     */
    public function name(): string;

    /**
     * @param UriInterface $redirectUri
     * @param array        $data
     *
     * @return ResponseInterface
     */
    public function buildResponse(UriInterface $redirectUri, array $data): ResponseInterface;
}
