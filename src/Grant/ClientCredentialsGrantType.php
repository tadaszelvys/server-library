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
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class ClientCredentialsGrantType implements GrantTypeSupportInterface
{
    use HasExceptionManager;

    /**
     * @var bool
     */
    private $issue_refresh_token_with_access_token = false;

    /**
     * ClientCredentialsGrantType constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'client_credentials';
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
        if (!$client instanceof ConfidentialClientInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'The client is not a confidential client');
        }
        $issue_refresh_token = $this->isRefreshTokenIssuedWithAccessToken();

        $grant_type_response->setResourceOwnerPublicId($client->getPublicId());
        $grant_type_response->setRefreshTokenIssued($issue_refresh_token);
        $grant_type_response->setRefreshTokenScope($grant_type_response->getRequestedScope());
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
