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

use Psr\Http\Message\ServerRequestInterface;

interface TokenTypeInterface
{
    /**
     * This function prepares token type information to be added to the token returned to the client.
     * It must adds 'token_type' value and should add additional information (e.g. key materials in MAC context).
     * A possible result:
     *  {
     *      "token_type":"mac", //Added by this method
     *      "kid":"22BIjxU93h/IgwEb4zCRu5WF37s=", //Added by this method
     *      "mac_key":"adijq39jdlaska9asud", //Added by this method
     *      "mac_algorithm":"hmac-sha-256" //Added by this method
     *  }.
     *
     * Another possible result:
     *  {
     *      "token_type":"Bearer", //Added by this method
     *      "custom_data":"baz", //Added by this method or by access token
     *  }.
     *
     * @return array
     */
    public function getTokenTypeInformation();

    /**
     * @return string
     */
    public function getTokenTypeName();

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    public function findToken(ServerRequestInterface $request);

    /**
     * @param \OAuth2\Token\AccessTokenInterface       $access_token
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    public function isTokenRequestValid(AccessTokenInterface $access_token, ServerRequestInterface $request);
}
