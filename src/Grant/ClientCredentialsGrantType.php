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

use OAuth2\Endpoint\Token\GrantTypeResponse;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientCredentialsGrantType implements GrantTypeInterface
{
    /**
     * @var bool
     */
    private $issueRefreshTokenWithAccessToken = false;

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
        return 'client_credentials';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponse &$grantTypeResponse)
    {
        $client = $request->getAttribute('client');
        if ($client->isPublic()) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT, 'error_description' => 'The client is not a confidential client.']);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, Client $client, GrantTypeResponse &$grantTypeResponse)
    {
        if (true === $this->isRefreshTokenIssuedWithAccessToken() ) {
            $grantTypeResponse = $grantTypeResponse->withMetadata('refresh_token', true);
        }

        $grantTypeResponse = $grantTypeResponse->withResourceOwner($client);
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuedWithAccessToken()
    {
        return $this->issueRefreshTokenWithAccessToken;
    }

    public function enableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issueRefreshTokenWithAccessToken = true;
    }

    public function disableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issueRefreshTokenWithAccessToken = false;
    }
}
