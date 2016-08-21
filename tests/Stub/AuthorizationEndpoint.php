<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Assert\Assertion;
use OAuth2\Behaviour\HasUserAccountManager;
use OAuth2\Endpoint\Authorization\AuthorizationEndpoint as Base;
use OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface;
use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationEndpoint extends Base
{
    use HasUserAccountManager;

    /**
     * @var null|string
     */
    private $current_user_account = null;

    /**
     * @var bool
     */
    private $current_user_fully_authenticated = true;

    /**
     * @var null|bool
     */
    private $is_authorized = null;

    /**
     * AuthorizationEndpoint constructor.
     *
     * @param \OAuth2\UserAccount\UserAccountManagerInterface                                                           $user_account_manager
     * @param \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface                                              $authorization_factory
     * @param \OAuth2\Scope\ScopeManagerInterface                                                                       $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                                               $exception_manager
     * @param \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface|null $pre_configured_authorization_manager
     */
    public function __construct(
        UserAccountManagerInterface $user_account_manager,
        AuthorizationFactoryInterface $authorization_factory,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager,
        PreConfiguredAuthorizationManagerInterface $pre_configured_authorization_manager = null
    ) {
        parent::__construct($authorization_factory, $scope_manager, $exception_manager, $pre_configured_authorization_manager);
        $this->setUserAccountManager($user_account_manager);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCurrentUserAccount()
    {
        return null === $this->current_user_account ? null : $this->getUserAccountManager()->getUserAccountByUsername($this->current_user_account);
    }

    /**
     * @param string $current_user_account
     */
    public function setCurrentUserAccount($current_user_account)
    {
        $this->current_user_account = $current_user_account;
    }

    /**
     * @param bool $current_user_fully_authenticate
     */
    public function setUserFullyAuthenticated($current_user_fully_authenticate)
    {
        $this->current_user_fully_authenticated = $current_user_fully_authenticate;
    }

    /**
     * @return bool|null
     */
    public function getIsAuthorized()
    {
        return $this->is_authorized;
    }

    /**
     * @param bool|null $is_authorized
     */
    public function setIsAuthorized($is_authorized)
    {
        Assertion::nullOrBoolean($is_authorized);
        $this->is_authorized = $is_authorized;
    }

    /**
     * {@inheritdoc}
     */
    protected function isCurrentUserFullyAuthenticated()
    {
        return $this->current_user_fully_authenticated;
    }

    /**
     * {@inheritdoc}
     */
    protected function redirectToLoginPage(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $response->getBody()->rewind();
        $response->getBody()->write('You are redirected to the login page');
    }

    /**
     * {@inheritdoc}
     */
    protected function processConsentScreen(AuthorizationInterface $authorization, ServerRequestInterface $request, ResponseInterface &$response)
    {
        if (is_bool($this->is_authorized)) {
            $authorization->setAuthorized($this->is_authorized);
            $this->processAuthorization($request, $response, $authorization);

            return;
        }

        $response->getBody()->rewind();
        $response->getBody()->write('You are on the consent screen');
    }
}
