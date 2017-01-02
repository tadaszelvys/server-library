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

use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccountRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class ResourceOwnerPasswordCredentialsGrantType implements GrantTypeInterface
{
    /**
     * @var bool
     */
    private $refreshTokenIssuanceAllowed = false;

    /**
     * @var bool
     */
    private $refreshTokenIssuanceForPublicClientsAllowed = false;

    /**
     * @var UserAccountRepositoryInterface
     */
    private $userAccountRepository;

    /**
     * @var OAuth2ResponseFactoryManagerInterface
     */
    private $responseFactoryManager;

    /**
     * ResourceOwnerPasswordCredentialsGrantType constructor.
     *
     * @param UserAccountRepositoryInterface        $userAccountRepository
     * @param OAuth2ResponseFactoryManagerInterface $responseFactoryManager
     */
    public function __construct(UserAccountRepositoryInterface $userAccountRepository, OAuth2ResponseFactoryManagerInterface $responseFactoryManager)
    {
        $this->userAccountRepository = $userAccountRepository;
        $this->responseFactoryManager = $responseFactoryManager;
    }

    public function allowRefreshTokenIssuance()
    {
        $this->refreshTokenIssuanceAllowed = true;
    }

    public function disallowRefreshTokenIssuance()
    {
        $this->refreshTokenIssuanceAllowed = false;
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuanceAllowed(): bool
    {
        return $this->refreshTokenIssuanceAllowed;
    }

    public function allowRefreshTokenIssuanceForPublicClients()
    {
        $this->refreshTokenIssuanceForPublicClientsAllowed = true;
    }

    public function disallowRefreshTokenIssuanceForPublicClients()
    {
        $this->refreshTokenIssuanceForPublicClientsAllowed = false;
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuanceForPublicClientsAllowed(): bool
    {
        return $this->refreshTokenIssuanceForPublicClientsAllowed;
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedResponseTypes(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType(): string
    {
        return 'password';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grantTypeResponse)
    {
        // Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, Client $client, GrantTypeResponseInterface &$grantTypeResponse)
    {
        $parsedBody = $request->getParsedBody();
        $username = $parsedBody['username'];
        $password = $parsedBody['password'];

        $userAccount = $this->userAccountRepository->getByUsername($username);
        if (null === $userAccount || !$this->userAccountRepository->isPasswordCredentialsValid($userAccount, $password)) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT,
                    'error_description' => 'Invalid username and password combination',
                ]
            );
        }

        $grantTypeResponse->setResourceOwnerPublicId($userAccount->getUserPublicId());
        $grantTypeResponse->setUserAccountPublicId($userAccount->getId());
        $grantTypeResponse->setRefreshTokenIssued($this->issueRefreshToken($client));
        $grantTypeResponse->setRefreshTokenScope($grantTypeResponse->getRequestedScope());
    }

    /**
     * @param Client $client
     *
     * @return bool
     */
    private function issueRefreshToken(Client $client): bool
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
