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
use OAuth2\Endpoint\Authorization\Exception\AuthorizeException;
use OAuth2\Endpoint\Authorization\Exception\CreateRedirectionException;
use OAuth2\Endpoint\Authorization\Exception\ShowConsentScreenException;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\UserAccount\UserAccountInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class PreConfiguredAuthorizationExtension implements AuthorizationEndpointExtensionInterface
{
    /**
     * @var \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface
     */
    private $pre_configured_authorization_manager;

    /**
     * PreConfiguredAuthorizationExtension constructor.
     *
     * @param \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface $pre_configured_authorization_manager
     */
    public function __construct(PreConfiguredAuthorizationManagerInterface $pre_configured_authorization_manager)
    {
        $this->pre_configured_authorization_manager = $pre_configured_authorization_manager;
    }

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
        $pre_configured_authorization = $this->findPreConfiguredAuthorization($authorization);

        if ($pre_configured_authorization instanceof PreConfiguredAuthorizationInterface) {
            if ($authorization->hasPrompt('consent')) {
                throw new ShowConsentScreenException($authorization);
            }

            $authorization->setAuthorized(true);
            throw new AuthorizeException($authorization);
        } else {
            if ($authorization->hasPrompt('none')) {
                throw new CreateRedirectionException($authorization, ExceptionManagerInterface::ERROR_INTERACTION_REQUIRED);
            }
        }
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
        $options['is_pre_configured_authorization_enabled'] = true;
    }

    /**
     * {@inheritdoc}
     */
    public function processAfterConsentScreenIsAccepted(AuthorizationInterface $authorization, array $form_data)
    {
        if (!array_key_exists('save_authorization', $form_data) || true !== $form_data['save_authorization']) {
            return;
        }

        $configuration = $this->getPreConfiguredAuthorizationManager()->createPreConfiguredAuthorization();
        $configuration->setClientPublicId($authorization->getClient()->getPublicId());
        $configuration->setResourceOwnerPublicId($authorization->getUserAccount()->getUserPublicId());
        $configuration->setUserAccountPublicId($authorization->getUserAccount()->getPublicId());
        $configuration->setScopes($authorization->getScopes());
        $this->getPreConfiguredAuthorizationManager()->savePreConfiguredAuthorization($configuration);
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     *
     * @return null|\OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface
     */
    private function findPreConfiguredAuthorization(AuthorizationInterface $authorization)
    {
        if (null !== $this->getPreConfiguredAuthorizationManager()) {
            return $this->getPreConfiguredAuthorizationManager()->findOnePreConfiguredAuthorization(
                $authorization->getUserAccount()->getUserPublicId(),
                $authorization->getClient()->getPublicId(),
                $authorization->getScopes()
            );
        }
    }

    /**
     * @return \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface
     */
    private function getPreConfiguredAuthorizationManager()
    {
        return $this->pre_configured_authorization_manager;
    }
}
