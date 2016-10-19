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

interface TokenTypeManagerInterface
{
    /**
     * @param \OAuth2\Token\TokenTypeInterface $token_type
     * @param bool                             $default
     */
    public function addTokenType(TokenTypeInterface $token_type, $default = false);

    /**
     * @return \OAuth2\Token\TokenTypeInterface[]
     */
    public function getTokenTypes();

    /**
     * @param string $token_type_name
     *
     * @return bool
     */
    public function hasTokenType($token_type_name);

    /**
     * @param string $token_type_name
     *
     * @return \OAuth2\Token\TokenTypeInterface
     */
    public function getTokenType($token_type_name);

    /**
     * @return \OAuth2\Token\TokenTypeInterface
     */
    public function getDefaultTokenType();

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param array                                    $additional_credential_values
     * @param \OAuth2\Token\TokenTypeInterface|null    $type
     *
     * @return string|null
     */
    public function findToken(ServerRequestInterface $request, array &$additional_credential_values, TokenTypeInterface &$type);

    /**
     * @param array $additional_authentication_parameters
     *
     * @return array
     */
    public function getTokenTypeSchemes(array $additional_authentication_parameters = []);
}
