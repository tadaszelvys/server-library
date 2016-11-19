<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Util;

use Psr\Http\Message\ServerRequestInterface;

class RequestBody
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return array
     */
    public static function getParameters(ServerRequestInterface $request)
    {
        $body = $request->getParsedBody();

        return is_array($body) ? $body : [];
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request   The request
     * @param string                                   $parameter The parameter
     *
     * @return string|null
     */
    public static function getParameter(ServerRequestInterface $request, $parameter)
    {
        $parameters = self::getParameters($request);

        return array_key_exists($parameter, $parameters) ? $parameters[$parameter] : null;
    }
}
