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

use OAuth2\Endpoint\Token\GrantTypeData;
use OAuth2\Model\Client\Client;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class RefreshTokenGrantType implements GrantTypeInterface
{
    /**
     * RefreshTokenGrantType constructor.
     *
     * @param RefreshTokenRepositoryInterface             $refresh_token_manager
     * @param OAuth2ResponseFactoryManagerInterface $response_factory_manager
     */
    public function __construct(RefreshTokenRepositoryInterface $refresh_token_manager, OAuth2ResponseFactoryManagerInterface $response_factory_manager)
    {
        $this->setRefreshTokenManager($refresh_token_manager);
        $this->setResponsefactoryManager($response_factory_manager);
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
        return 'refresh_token';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareTokenResponse(ServerRequestInterface $request, GrantTypeData &$grant_type_response)
    {
        // Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function grant(ServerRequestInterface $request, Client $client, GrantTypeData &$grant_type_response)
    {
        $refresh_token = RequestBody::getParameter($request, 'refresh_token');
        if (null === $refresh_token) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'No \'refresh_token\' parameter found']);
        }

        $token = $this->getRefreshTokenManager()->getRefreshToken($refresh_token);

        if (!$token instanceof RefreshToken) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT, 'error_description' => 'Invalid refresh token']);
        }

        $this->checkRefreshToken($token, $client);

        if (empty($grant_type_response->getRequestedScope())) {
            $grant_type_response->setRequestedScope($token->getScope());
        }
        $grant_type_response->setAvailableScope($token->getScope());
        $grant_type_response->setResourceOwnerPublicId($token->getResourceOwnerPublicId());
        $grant_type_response->setUserAccountPublicId($token->getUserAccountPublicId());
        $grant_type_response->setRefreshTokenIssued(true);
        $grant_type_response->setRefreshTokenScope($token->getScope());
        $grant_type_response->setRefreshTokenRevoked($token);
        $grant_type_response->setAdditionalData('metadatas', $token->getMetadatas());
    }

    /**
     * {@inheritdoc}
     */
    public function checkRefreshToken(RefreshToken $token, Client $client)
    {
        if ($client->getPublicId() !== $token->getClientPublicId()) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT, 'error_description' => 'Invalid refresh token']);
        }

        if ($token->hasExpired()) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT, 'error_description' => 'Refresh token has expired']);
        }
    }
}
