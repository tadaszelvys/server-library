<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasUserAccountManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\UserAccount\IssueRefreshTokenExtensionInterface;
use OAuth2\UserAccount\UserAccountInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class ResourceOwnerPasswordCredentialsGrantType implements GrantTypeInterface
{
    use HasExceptionManager;
    use HasUserAccountManager;

    /**
     * @var bool
     */
    private $issue_refresh_token_with_access_token = true;

    /**
     * ResourceOwnerPasswordCredentialsGrantType constructor.
     *
     * @param \OAuth2\UserAccount\UserAccountManagerInterface $user_account_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(
        UserAccountManagerInterface $user_account_manager,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setUserAccountManager($user_account_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedResponseTypes()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'password';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response)
    {
        // Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response)
    {
        $username = RequestBody::getParameter($request, 'username');
        $password = RequestBody::getParameter($request, 'password');

        $user_account = $this->getUserAccountManager()->getUserAccountByUsername($username);
        if (null === $user_account || !$this->getUserAccountManager()->checkUserAccountPasswordCredentials($user_account, $password)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, 'Invalid username and password combination');
        }

        $grant_type_response->setResourceOwnerPublicId($user_account->getUserPublicId());
        $grant_type_response->setUserAccountPublicId($user_account->getPublicId());
        $grant_type_response->setRefreshTokenIssued($this->getIssueRefreshToken($client, $user_account));
        $grant_type_response->setRefreshTokenScope($grant_type_response->getRequestedScope());
    }

    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\UserAccount\UserAccountInterface $user_account
     *
     * @return bool
     */
    private function getIssueRefreshToken(ClientInterface $client, UserAccountInterface $user_account)
    {
        if ($user_account instanceof IssueRefreshTokenExtensionInterface && false === $user_account->isRefreshTokenIssuanceAllowed($client, 'password')) {
            return false;
        }

        return $this->isRefreshTokenIssuedWithAccessToken();
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuedWithAccessToken()
    {
        return $this->issue_refresh_token_with_access_token;
    }

    public function enableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issue_refresh_token_with_access_token = true;
    }

    public function disableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issue_refresh_token_with_access_token = false;
    }
}
