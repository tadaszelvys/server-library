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

use Assert\Assertion;
use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Endpoint\Authorization\Exception\RedirectToLoginPageException;
use OAuth2\Model\IdToken\IdTokenRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class IdTokenHintExtension implements AuthorizationEndpointExtensionInterface
{
    /**
     * IdTokenHintExtension constructor.
     *
     * @param IdTokenRepositoryInterface     $id_token_manager
     * @param UserAccountRepositoryInterface $user_account_manager
     */
    public function __construct(IdTokenRepositoryInterface $id_token_manager, UserAccountRepositoryInterface $user_account_manager)
    {
        $this->setIdTokenManager($id_token_manager);
        $this->setUserAccountManager($user_account_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function processUserAccount(ServerRequestInterface $request, Authorization $authorization, UserAccount &$user_account = null)
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
                    if ($user_account->getId() !== $public_id) {
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
    public function processAfterUserAccountComputation(UserAccount $user_account, $is_fully_authenticated, ServerRequestInterface $request, Authorization $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, Authorization $authorization)
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
