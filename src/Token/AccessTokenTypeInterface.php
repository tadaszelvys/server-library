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

interface AccessTokenTypeInterface
{
    /**
     * This function prepare the access token to be sent to the client.
     * It adds 'token_type' value and additional information (e.g. key materials in MAC context).
     * A possible result:
     *  {
     *      "access_token": "foo", //From access token
     *      "refresh_token":"8xLOxBtZp8", //From access token
     *      "expires_in":3600, //From access token
     *      "token_type":"mac", //Added by this method
     *      "kid":"22BIjxU93h/IgwEb4zCRu5WF37s=", //Added by this method
     *      "mac_key":"adijq39jdlaska9asud", //Added by this method
     *      "mac_algorithm":"hmac-sha-256" //Added by this method
     *  }
     * Another possible result:
     *  {
     *      "access_token": "bar", //From access token
     *      "expires_in":3600, //From access token
     *      "token_type":"Bearer", //Added by this method
     *      "custom_data":"baz", //Added by this method or by access token
     *  }.
     *
     * @param \OAuth2\Token\AccessTokenInterface $token The access token to update
     */
    public function updateAccessToken(AccessTokenInterface &$token);

    /**
     * @return string
     */
    public function getTokenTypeName();
}
