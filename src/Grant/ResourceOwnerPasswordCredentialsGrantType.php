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
use OAuth2\Behaviour\HasUserManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\User\IssueRefreshTokenExtensionInterface;
use OAuth2\User\UserInterface;
use OAuth2\User\UserManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class ResourceOwnerPasswordCredentialsGrantType implements GrantTypeInterface
{
    use HasExceptionManager;
    use HasUserManager;

    /**
     * @var bool
     */
    private $issue_refresh_token_with_access_token = true;

    /**
     * ResourceOwnerPasswordCredentialsGrantType constructor.
     *
     * @param \OAuth2\User\UserManagerInterface           $user_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(
        UserManagerInterface $user_manager,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setUserManager($user_manager);
        $this->setExceptionManager($exception_manager);
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
    public function isSupported(array $request_parameters)
    {
        if (array_key_exists('grant_type', $request_parameters)) {
            return $this->getGrantType() === $request_parameters['grant_type'];
        }

        return false;
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

        $user = $this->getUserManager()->getUserByUsername($username);
        if (null === $user || !$this->getUserManager()->checkUserPasswordCredentials($user, $password)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, 'Invalid username and password combination');
        }

        $grant_type_response->setResourceOwnerPublicId($user->getPublicId());
        $grant_type_response->setRefreshTokenIssued($this->getIssueRefreshToken($client, $user));
        $grant_type_response->setRefreshTokenScope($grant_type_response->getRequestedScope());
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param \OAuth2\User\UserInterface     $user
     *
     * @return bool
     */
    private function getIssueRefreshToken(ClientInterface $client, UserInterface $user)
    {
        if ($user instanceof IssueRefreshTokenExtensionInterface && false === $user->isRefreshTokenIssuanceAllowed($client, 'password')) {
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
