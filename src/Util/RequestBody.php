<?php

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
        return $request->getParsedBody();
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
