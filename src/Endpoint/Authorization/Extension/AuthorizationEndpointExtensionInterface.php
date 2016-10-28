<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\Extension;

use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use OAuth2\UserAccount\UserAccountInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationEndpointExtensionInterface
{
    /**
     * @param array                                                 $response_parameters
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param \OAuth2\UserAccount\UserAccountInterface|null         $user_account
     */
    public function processUserAccount(ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization, UserAccountInterface &$user_account = null);

    /**
     * @param \OAuth2\UserAccount\UserAccountInterface              $user_account
     * @param bool                                                  $is_fully_authenticated
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    public function processUserAccountIsAvailable(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    public function processUserAccountIsNotAvailable(ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization);

    /**
     * @param \OAuth2\UserAccount\UserAccountInterface              $user_account
     * @param bool                                                  $is_fully_authenticated
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    public function processAfterUserAccountComputation(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization);

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param array                                                 $options
     */
    public function processConsentScreenOptions(AuthorizationInterface $authorization, array &$options);

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param array                                                 $form_data
     */
    public function processAfterConsentScreenIsAccepted(AuthorizationInterface $authorization, array $form_data);
}
