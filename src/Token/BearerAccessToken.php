<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

class BearerAccessToken implements AccessTokenTypeInterface
{
    use HasExceptionManager;

    /**
     * ClientCredentialsGrantType constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * Get the list of methods to find the access token
     * This method can be override to add new way to find an access token.
     * These methods are those official supported by the RFC6750.
     *
     * @return string[]
     */
    protected function getTokenFromMethods()
    {
        return [
            'getTokenFromHeaders',
            'getTokenFromRequestBody',
            'getTokenFromQuery',
        ];
    }

    /**
     * Get the token from the authorization header.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    protected function getTokenFromHeaders(ServerRequestInterface $request)
    {
        $header = $request->getHeader('AUTHORIZATION');

        if (0 === count($header)) {
            return;
        }

        if (!preg_match('/'.preg_quote('Bearer', '/').'\s([a-zA-Z0-9\-_\+~\/\.]+)/', $header[0], $matches)) {
            return;
        }

        $token = $matches[1];

        return $token;
    }

    /**
     * Get the token from the request body.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    protected function getTokenFromRequestBody(ServerRequestInterface $request)
    {
        return RequestBody::getParameter($request, 'access_token');
    }

    /**
     * Get the token from the query string.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    protected function getTokenFromQuery(ServerRequestInterface $request)
    {
        $query_params = $request->getQueryParams();

        return array_key_exists('access_token', $query_params) ? $query_params['access_token'] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function updateAccessToken(AccessTokenInterface &$token)
    {
        $token->setTokenType('Bearer');
    }

    /**
     * {@inheritdoc}
     */
    public function findAccessToken(ServerRequestInterface $request)
    {
        $tokens = [];
        $methods = $this->getTokenFromMethods();

        foreach ($methods as $method) {
            $token = $this->$method($request);

            if (null !== $token) {
                $tokens[] = $token;
            }
        }

        if (count($tokens) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one method may be used to authenticate at a time.');
        } elseif (empty($tokens)) {
            return;
        }

        $accessToken = current($tokens);
        if (!is_string($accessToken)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'A method returned an invalid data type.');
        }

        return $accessToken;
    }

    /**
     * This token type does not require extra-check.
     *
     * {@inheritdoc}
     */
    public function isAccessTokenRequestValid(ServerRequestInterface $request, AccessTokenInterface $token)
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeName()
    {
        return 'bearer';
    }
}
