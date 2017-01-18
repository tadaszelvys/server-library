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

namespace OAuth2\Test\Stub;

use Assert\Assertion;
use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Endpoint\Authorization\AuthorizationEndpoint as Base;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Response\OAuth2Exception;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationEndpoint extends Base
{
    /**
     * @var null|UserAccount
     */
    private $currentUserAccount = null;

    /**
     * @var bool
     */
    private $currentUserFullyAuthenticated = true;

    /**
     * @var null|bool
     */
    private $isAuthorized = null;

    /**
     * {@inheritdoc}
     */
    protected function getCurrentUserAccount()
    {
        return $this->currentUserAccount;
    }

    /**
     * @param UserAccount|null $currentUserAccount
     */
    public function setCurrentUserAccount(UserAccount $currentUserAccount = null)
    {
        $this->currentUserAccount = $currentUserAccount;
    }

    /**
     * @param bool $current_user_fully_authenticate
     */
    public function setUserFullyAuthenticated($current_user_fully_authenticate)
    {
        $this->currentUserFullyAuthenticated = $current_user_fully_authenticate;
    }

    /**
     * @return bool|null
     */
    public function getIsAuthorized()
    {
        return $this->isAuthorized;
    }

    /**
     * @param bool|null $isAuthorized
     */
    public function setIsAuthorized($isAuthorized)
    {
        Assertion::nullOrBoolean($isAuthorized);
        $this->isAuthorized = $isAuthorized;
    }

    /**
     * {@inheritdoc}
     */
    protected function isCurrentUserFullyAuthenticated()
    {
        return $this->currentUserFullyAuthenticated;
    }

    /**
     * {@inheritdoc}
     */
    protected function redirectToLoginPage(Authorization $authorization, ServerRequestInterface $request)
    {
        throw new OAuth2Exception(
            200,
            'You are redirected to the login page'
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function processConsentScreen(Authorization $authorization, ServerRequestInterface $request)
    {
        if (is_bool($this->isAuthorized)) {
            $authorization = $authorization->setAuthorized($this->isAuthorized);
            $this->processAuthorization($request, $authorization);

            return [
                'save_authorization' => true,
            ];
        }

        throw new OAuth2Exception(
            200,
            'You are on the consent screen'
        );
    }
}
