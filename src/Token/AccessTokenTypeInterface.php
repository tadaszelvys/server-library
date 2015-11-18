<?php

namespace OAuth2\Token;

use Psr\Http\Message\ServerRequestInterface;

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
     * @param \OAuth2\Token\AccessTokenInterface $token The access token to prepare
     *
     * @return array Return the access token information with optional key materials and additional information
     */
    public function prepareAccessToken(AccessTokenInterface $token);

    /**
     * Tries to find an access token in the request.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     *
     * @return string|null The access token
     */
    public function findAccessToken(ServerRequestInterface $request);

    /**
     * This method verifies the access token request is valid.
     * Be careful: it MUST not verify the access token itself.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Token\AccessTokenInterface       $token
     *
     * @return bool True if the access token request is valid, else false
     */
    public function isAccessTokenRequestValid(ServerRequestInterface $request, AccessTokenInterface $token);

    /**
     * @return array
     */
    public function getSchemeParameters();
}
