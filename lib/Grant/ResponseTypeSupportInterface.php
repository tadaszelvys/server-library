<?php

namespace OAuth2\Grant;

use OAuth2\Endpoint\AuthorizationInterface;

interface ResponseTypeSupportInterface
{
    /**
     * This function returns the supported response type.
     *
     * @return string The response type
     * @return bool   Return true if it can handle the request
     */
    public function getResponseType();

    /**
     * This is the authorization endpoint of the grant type
     * This function checks the request and returns authorize or not the client.
     *
     * @param \OAuth2\Endpoint\AuthorizationInterface $authorization The authorization object
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    public function grantAuthorization(AuthorizationInterface $authorization);

    /**
     * Returns the response mode of the response type or the error returned.
     * Possible values are 'query' (in the query string) or 'fragment' (in the fragment URI).
     *
     * @return string
     */
    public function getResponseMode();
}
