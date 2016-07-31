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
use OAuth2\Behaviour\HasUserManager;
use OAuth2\Endpoint\Authorization\AuthorizationEndpoint as Base;
use OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface;
use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\User\UserManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationEndpoint extends Base
{
    use HasUserManager;

    /**
     * @var null|string
     */
    private $current_user = null;

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
     * @param \OAuth2\User\UserManagerInterface                                                                         $user_manager
     * @param \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface                                              $authorization_factory
     * @param \OAuth2\Scope\ScopeManagerInterface                                                                       $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                                               $exception_manager
     * @param \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface|null $pre_configured_authorization_manager
     */
    public function __construct(
        UserManagerInterface $user_manager,
        AuthorizationFactoryInterface $authorization_factory,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager,
        PreConfiguredAuthorizationManagerInterface $pre_configured_authorization_manager = null
    ) {
        parent::__construct($authorization_factory, $scope_manager, $exception_manager, $pre_configured_authorization_manager);
        $this->setUserManager($user_manager);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCurrentUser()
    {
        return null === $this->current_user ? null : $this->getUserManager()->getUserByUsername($this->current_user);
    }

    /**
     * @param string $current_user
     */
    public function setCurrentUser($current_user)
    {
        $this->current_user = $current_user;
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
