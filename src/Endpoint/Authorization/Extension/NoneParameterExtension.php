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
use OAuth2\Endpoint\Authorization\Exception\CreateRedirectionException;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\UserAccount\UserAccountInterface;
use Psr\Http\Message\ServerRequestInterface;

class NoneParameterExtension implements AuthorizationEndpointExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function processUserAccount(ServerRequestInterface $request, AuthorizationInterface $authorization, UserAccountInterface &$user_account = null)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccountIsAvailable(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, AuthorizationInterface $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccountIsNotAvailable(ServerRequestInterface $request, AuthorizationInterface $authorization)
    {
        if ($authorization->hasPrompt('none')) {
            throw new CreateRedirectionException($authorization, OAuth2ResponseFactoryManagerInterface::ERROR_LOGIN_REQUIRED);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function processAfterUserAccountComputation(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, AuthorizationInterface $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, AuthorizationInterface $authorization)
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
