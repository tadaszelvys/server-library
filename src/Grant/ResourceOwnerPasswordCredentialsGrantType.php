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
    private $refresh_token_issuance_allowed = false;

    /**
     * @var bool
     */
    private $refresh_token_issuance_for_public_clients_allowed = false;

    /**
     * ResourceOwnerPasswordCredentialsGrantType constructor.
     *
     * @param \OAuth2\UserAccount\UserAccountManagerInterface $user_account_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(UserAccountManagerInterface $user_account_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setUserAccountManager($user_account_manager);
        $this->setExceptionManager($exception_manager);
    }

    public function allowRefreshTokenIssuance()
    {
        $this->refresh_token_issuance_allowed = true;
    }

    public function disallowRefreshTokenIssuance()
    {
        $this->refresh_token_issuance_allowed = false;
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuanceAllowed()
    {
        return $this->refresh_token_issuance_allowed;
    }

    public function allowRefreshTokenIssuanceForPublicClients()
    {
        $this->refresh_token_issuance_for_public_clients_allowed = true;
    }

    public function disallowRefreshTokenIssuanceForPublicClients()
    {
        $this->refresh_token_issuance_for_public_clients_allowed = false;
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuanceForPublicClientsAllowed()
    {
        return $this->refresh_token_issuance_for_public_clients_allowed;
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
        $grant_type_response->setRefreshTokenIssued($this->issueRefreshToken($client));
        $grant_type_response->setRefreshTokenScope($grant_type_response->getRequestedScope());
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return bool
     */
    private function issueRefreshToken(ClientInterface $client)
    {
        if (!$this->isRefreshTokenIssuanceAllowed()) {
            return false;
        }

        if (true === $client->isPublic()) {
            return $this->isRefreshTokenIssuanceForPublicClientsAllowed();
        }

        return true;
    }
}
