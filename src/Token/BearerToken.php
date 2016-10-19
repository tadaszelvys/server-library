<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Assert\Assertion;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

class BearerToken implements TokenTypeInterface
{
    /**
     * @var null|string
     */
    private $realm = null;

    /**
     * @var bool
     */
    private $token_from_authorization_header_allowed = true;

    /**
     * @var bool
     */
    private $token_from_request_body_allowed = false;

    /**
     * @var bool
     */
    private $token_from_query_string_allowed = false;

    /**
     * BearerToken constructor.
     *
     * @param null|string $realm
     */
    public function __construct($realm = null)
    {
        Assertion::nullOrString($realm, 'The "realm" should be null or a string');
        $this->realm = $realm;
    }

    /**
     * @return bool
     */
    public function isTokenFromAuthorizationHeaderAllowed()
    {
        return $this->token_from_authorization_header_allowed;
    }

    public function allowTokenFromAuthorizationHeader()
    {
        $this->token_from_authorization_header_allowed = true;
    }

    public function disallowTokenFromAuthorizationHeader()
    {
        $this->token_from_authorization_header_allowed = false;
    }

    /**
     * @return bool
     */
    public function isTokenFromRequestBodyAllowed()
    {
        return $this->token_from_request_body_allowed;
    }

    public function allowTokenFromRequestBody()
    {
        $this->token_from_request_body_allowed = true;
    }

    public function disallowTokenFromRequestBody()
    {
        $this->token_from_request_body_allowed = false;
    }

    /**
     * @return bool
     */
    public function isTokenFromQueryStringAllowed()
    {
        return $this->token_from_query_string_allowed;
    }

    public function allowTokenFromQueryString()
    {
        $this->token_from_query_string_allowed = true;
    }

    public function disallowTokenFromQueryString()
    {
        $this->token_from_query_string_allowed = false;
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeName()
    {
        return 'Bearer';
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeScheme()
    {
        $scheme = $this->getTokenTypeName();
        if (null !== $this->realm) {
            $scheme = sprintf('%s realm="%s"', $scheme, $this->realm);
        }

        return $scheme;
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeInformation()
    {
        return [
            'token_type' => $this->getTokenTypeName(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function findToken(ServerRequestInterface $request, array &$additional_credential_values)
    {
        $methods = [
            'isTokenFromAuthorizationHeaderAllowed' => 'getTokenFromAuthorizationHeaders',
            'isTokenFromQueryStringAllowed'         => 'getTokenFromQuery',
            'isTokenFromRequestBodyAllowed'         => 'getTokenFromRequestBody',
        ];

        foreach ($methods as $test => $method) {
            if (true === $this->$test() && null !== $token = $this->$method($request)) {
                return $token;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isTokenRequestValid(AccessTokenInterface $access_token, ServerRequestInterface $request, array $additional_credential_values)
    {
        if ($access_token->getTokenType() !== $this->getTokenTypeName()) {
            return false;
        }

        return true;
    }

    /**
     * Get the token from the authorization header.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    protected function getTokenFromAuthorizationHeaders(ServerRequestInterface $request)
    {
        $authorization_headers = $request->getHeader('AUTHORIZATION');

        if (0 === count($authorization_headers)) {
            return;
        }

        foreach ($authorization_headers as $authorization_header) {
            if (1 === preg_match('/'.preg_quote('Bearer', '/').'\s([a-zA-Z0-9\-_\+~\/\.]+)/', $authorization_header, $matches)) {
                return $matches[1];
            }
        }
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
}
