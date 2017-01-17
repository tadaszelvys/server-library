<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\GrantType;

use OAuth2\Endpoint\Token\GrantTypeData;
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
     * ResourceOwnerPasswordCredentialsGrantType constructor.
     *
     * @param UserAccountRepositoryInterface        $userAccountRepository
     */
    public function __construct(UserAccountRepositoryInterface $userAccountRepository)
    {
        $this->userAccountRepository = $userAccountRepository;
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

    public function checkTokenRequest(ServerRequestInterface $request)
    {
        $parameters = $request->getParsedBody() ?? [];
        $requiredParameters = ['username', 'password'];

        foreach ($requiredParameters as $requiredParameter) {
            if (!array_key_exists($requiredParameter, $parameters)) {
                throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => sprintf('The parameter \'%s\' is missing.', $requiredParameter)]);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepareTokenResponse(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData
    {
        // Nothing to do
        return $grantTypeResponse;
    }

    /**
     * {@inheritdoc}
     */
    public function grant(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData
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
                    'error_description' => 'Invalid username and password combination.',
                ]
            );
        }

        $grantTypeResponse = $grantTypeResponse->withResourceOwner($userAccount);
        if ($this->issueRefreshToken($grantTypeResponse->getClient())) {
            $grantTypeResponse = $grantTypeResponse->withRefreshToken();
        } else {
            $grantTypeResponse = $grantTypeResponse->withRefreshToken();
            $grantTypeResponse->withRefreshTokenScopes($grantTypeResponse->getScopes());
        }

        return $grantTypeResponse;
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
