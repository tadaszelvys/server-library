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

use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Model\UserAccount\UserAccount;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationEndpointExtensionInterface
{
    /**
     * @param array                  $response_parameters
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, Authorization $authorization);

    /**
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     * @param UserAccount|null       $user_account
     */
    public function processUserAccount(ServerRequestInterface $request, Authorization $authorization, UserAccount &$user_account = null);

    /**
     * @param UserAccount            $user_account
     * @param bool                   $is_fully_authenticated
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    public function processUserAccountIsAvailable(UserAccount $user_account, $is_fully_authenticated, ServerRequestInterface $request, Authorization $authorization);

    /**
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    public function processUserAccountIsNotAvailable(ServerRequestInterface $request, Authorization $authorization);

    /**
     * @param UserAccount            $user_account
     * @param bool                   $is_fully_authenticated
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    public function processAfterUserAccountComputation(UserAccount $user_account, $is_fully_authenticated, ServerRequestInterface $request, Authorization $authorization);

    /**
     * @param Authorization $authorization
     * @param array         $options
     */
    public function processConsentScreenOptions(Authorization $authorization, array &$options);

    /**
     * @param Authorization $authorization
     * @param array         $form_data
     */
    public function processAfterConsentScreenIsAccepted(Authorization $authorization, array $form_data);
}
