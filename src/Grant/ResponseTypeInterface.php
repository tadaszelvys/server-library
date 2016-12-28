<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Endpoint\Authorization\Authorization;

interface ResponseTypeInterface
{
    const RESPONSE_TYPE_MODE_FRAGMENT = 'fragment';
    const RESPONSE_TYPE_MODE_QUERY = 'query';
    const RESPONSE_TYPE_MODE_FORM_POST = 'form_post';

    /**
     * This function returns the supported response type.
     *
     * @return string
     */
    public function getResponseType(): string;

    /**
     * This function returns the list of associated grant types.
     *
     * @return string[]
     */
    public function getAssociatedGrantTypes(): array;

    /**
     * Returns the response mode of the response type or the error returned.
     * For possible values, see constants above.
     *
     * @return string
     */
    public function getResponseMode(): string;

    /**
     * This function checks the authorization.
     *
     * @param \OAuth2\Endpoint\Authorization\Authorization $authorization The authorization object
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return array
     */
    public function checkAuthorization(Authorization $authorization);

    /**
     * This function checks the request and prepare the authorization response.
     *
     * @param \OAuth2\Endpoint\Authorization\Authorization $authorization The authorization object
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return array
     */
    public function prepareAuthorization(Authorization $authorization);

    /**
     * This function finish the authorization response.
     *
     * @param \OAuth2\Endpoint\Authorization\Authorization $authorization       The authorization object
     * @param array                                        $response_parameters The parameters to send to the client
     * @param string                                       $redirect_uri        The redirect URI
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return array
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, $redirect_uri);
}
