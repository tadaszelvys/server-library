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
use OAuth2\Endpoint\Authorization\AuthorizationEndpoint as Base;
use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationEndpoint extends Base
{
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
    protected function redirectToLoginPage(AuthorizationInterface $authorization, ServerRequestInterface $request, ResponseInterface &$response)
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

            return [
                'save_authorization' => true,
            ];
        }

        $response->getBody()->rewind();
        $response->getBody()->write('You are on the consent screen');
    }
}
