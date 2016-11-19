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

use Assert\Assertion;
use OAuth2\Behaviour\HasUserAccountManager;
use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use OAuth2\Endpoint\Authorization\Exception\CreateRedirectionException;
use OAuth2\Endpoint\Authorization\Exception\RedirectToLoginPageException;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\OpenIdConnect\HasIdTokenManager;
use OAuth2\OpenIdConnect\IdTokenManagerInterface;
use OAuth2\UserAccount\UserAccountInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class IdTokenHintExtension implements AuthorizationEndpointExtensionInterface
{
    use HasIdTokenManager;
    use HasUserAccountManager;

    /**
     * IdTokenHintExtension constructor.
     *
     * @param \OAuth2\OpenIdConnect\IdTokenManagerInterface   $id_token_manager
     * @param \OAuth2\UserAccount\UserAccountManagerInterface $user_account_manager
     */
    public function __construct(IdTokenManagerInterface $id_token_manager, UserAccountManagerInterface $user_account_manager)
    {
        $this->setIdTokenManager($id_token_manager);
        $this->setUserAccountManager($user_account_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccount(ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization, UserAccountInterface &$user_account = null)
    {
        // The query parameter 'id_token_hint' and the Id Token Manager are set
        if ($authorization->hasQueryParam('id_token_hint') && null !== $this->getIdTokenManager()) {
            try {
                $id_token_hint = $this->getIdTokenManager()->loadIdToken($authorization->getQueryParam('id_token_hint'));
                Assertion::true($id_token_hint->hasClaim('sub'), 'Invalid "id_token_hint" parameter.');
                $public_id = $this->getIdTokenManager()->getPublicIdFromSubjectIdentifier($id_token_hint->getClaim('sub'));
                Assertion::notNull($public_id, 'Invalid "id_token_hint" parameter.');
                if (null === $user_account) {
                    $user_account = $this->getUserAccountManager()->getUserAccountByPublicId($public_id);
                } else {
                    if ($user_account->getPublicId() !== $public_id) {
                        throw new RedirectToLoginPageException($authorization);
                    }
                }
            } catch (\InvalidArgumentException $e) {
                throw new CreateRedirectionException($authorization, ExceptionManagerInterface::BAD_REQUEST, $e->getMessage());
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccountIsAvailable(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization)
    {
        //Nothing to do
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
