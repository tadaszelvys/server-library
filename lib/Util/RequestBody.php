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
        $parameters = array();
        if (count($request->getHeader('CONTENT-TYPE')) < 1) {
            return $parameters;
        }

        if (!preg_match('/^application\/x-www-form-urlencoded([\s|;].*)?$/', $request->getHeader('CONTENT-TYPE')[0])) {
            return $parameters;
        }

        $request->getBody()->rewind();
        $body = $request->getBody()->getContents();
        if (!is_string($body)) {
            return $parameters;
        }
        parse_str($body, $parameters);
        return $parameters;
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
