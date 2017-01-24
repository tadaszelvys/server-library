<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization\Extension;

use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Model\UserAccount\UserAccount;
use Psr\Http\Message\ServerRequestInterface;

class StateParameterExtension implements AuthorizationEndpointExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function processUserAccount(ServerRequestInterface $request, Authorization $authorization, UserAccount &$user_account = null)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, Authorization $authorization)
    {
        if ($authorization->hasQueryParam(('state'))) {
            $response_parameters['state'] = $authorization->getQueryParam('state');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccountIsAvailable(UserAccount $user_account, bool $is_fully_authenticated, ServerRequestInterface $request, Authorization $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccountIsNotAvailable(ServerRequestInterface $request, Authorization $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processAfterUserAccountComputation(UserAccount $user_account, bool $is_fully_authenticated, ServerRequestInterface $request, Authorization $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processConsentScreenOptions(Authorization $authorization, array &$options)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function processAfterConsentScreenIsAccepted(Authorization $authorization, array $form_data)
    {
        //Nothing to do
    }
}
