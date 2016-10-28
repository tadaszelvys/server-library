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
use OAuth2\Endpoint\Authorization\Exception\RedirectToLoginPageException;
use OAuth2\UserAccount\UserAccountInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class LoginParameterExtension implements AuthorizationEndpointExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function processUserAccount(ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization, UserAccountInterface &$user_account = null)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccountIsAvailable(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization)
    {
        if ($authorization->hasPrompt('login') && !$is_fully_authenticated) {
            throw new RedirectToLoginPageException($authorization);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccountIsNotAvailable(ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processAfterUserAccountComputation(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processConsentScreenOptions(AuthorizationInterface $authorization, array &$options)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processAfterConsentScreenIsAccepted(AuthorizationInterface $authorization, array $form_data)
    {
        //Nothing to do
    }
}
