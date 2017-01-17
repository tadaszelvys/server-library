<?php

declare(strict_types=1);

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
use OAuth2\Endpoint\Authorization\Exception\RedirectToLoginPageException;
use OAuth2\OpenIdConnect\HasIdTokenManager;
use OAuth2\OpenIdConnect\IdTokenManagerInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\UserAccount\UserAccountInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class IdTokenHintExtension implements AuthorizationEndpointExtensionInterface
{
    use HasIdTokenManager;
    use HasUserAccountManager;

    /**
     * @var \OAuth2\Response\OAuth2ResponseFactoryManagerInterface
     */
    private $response_factory;

    /**
     * IdTokenHintExtension constructor.
     *
     * @param \OAuth2\Response\OAuth2ResponseFactoryManagerInterface $response_factory
     * @param \OAuth2\OpenIdConnect\IdTokenManagerInterface          $id_token_manager
     * @param \OAuth2\UserAccount\UserAccountManagerInterface        $user_account_manager
     */
    public function __construct(OAuth2ResponseFactoryManagerInterface $response_factory, IdTokenManagerInterface $id_token_manager, UserAccountManagerInterface $user_account_manager)
    {
        $this->response_factory = $response_factory;
        $this->setIdTokenManager($id_token_manager);
        $this->setUserAccountManager($user_account_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccount(ServerRequestInterface $request, AuthorizationInterface $authorization, UserAccountInterface &$user_account = null)
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
                throw new OAuth2Exception($this->response_factory->getResponse(302, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => $e->getMessage()]));
            }
        }
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
        //Nothing to do
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
