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
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class RefreshTokenGrantType implements GrantTypeSupportInterface
{
    use HasExceptionManager;
    use HasRefreshTokenManager;

    /**
     * RefreshTokenGrantType constructor.
     *
     * @param \OAuth2\Token\RefreshTokenManagerInterface  $refresh_token_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(RefreshTokenManagerInterface $refresh_token_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setRefreshTokenManager($refresh_token_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'refresh_token';
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
        $refresh_token = RequestBody::getParameter($request, 'refresh_token');
        if (null === $refresh_token) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'No "refresh_token" parameter found');
        }

        $token = $this->getRefreshTokenManager()->getRefreshToken($refresh_token);

        if (!$token instanceof RefreshTokenInterface || $token->isUsed()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, 'Invalid refresh token');
        }

        $this->checkRefreshToken($token, $client);

        if (empty($grant_type_response->getRequestedScope())) {
            $grant_type_response->setRequestedScope($token->getScope());
        }
        $grant_type_response->setAvailableScope($token->getScope());
        $grant_type_response->setResourceOwnerPublicId($token->getResourceOwnerPublicId());
        $grant_type_response->setRefreshTokenIssued(true);
        $grant_type_response->setRefreshTokenScope($token->getScope());
        $grant_type_response->setRefreshTokenRevoked($token);
    }

    /**
     * {@inheritdoc}
     */
    public function checkRefreshToken(RefreshTokenInterface $token, ClientInterface $client)
    {
        if ($client->getPublicId() !== $token->getClientPublicId()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, 'Invalid refresh token');
        }

        if ($token->hasExpired()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, 'Refresh token has expired');
        }
    }
}
