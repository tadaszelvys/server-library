<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect;

use OAuth2\Command\IdToken\CreateIdTokenCommand;
use OAuth2\DataTransporter;
use OAuth2\Endpoint\Token\TokenEndpointExtensionInterface;
use OAuth2\Endpoint\Token\GrantTypeResponse;
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\Client\Client;
use OAuth2\Model\IdToken\IdToken;
use OAuth2\Model\UserAccount\UserAccount;
use SimpleBus\Message\Bus\MessageBus;

/**
 * Class OpenIdConnectTokenEndpointExtension.
 */
class OpenIdConnectTokenEndpointExtension implements TokenEndpointExtensionInterface
{
    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * OpenIdConnectTokenEndpointExtension constructor.
     * @param MessageBus $commandBus
     */
    public function __construct(MessageBus $commandBus)
    {
        $this->commandBus = $commandBus;
    }

    /**
     * {@inheritdoc].
     */
    public function postAccessTokenCreation(Client $client, GrantTypeResponse &$grantTypeResponse, AccessToken $accessToken)
    {
        if (false === $this->issueIdToken($grantTypeResponse) || !$grantTypeResponse->hasMetadata('redirect_uri')) {
            return;
        }
        $user = $grantTypeResponse->getResourceOwner();
        if (!$grantTypeResponse->getResourceOwner() instanceof UserAccount) {
            return;
        }

        $claims = [];
        $authCode = $grantTypeResponse->getMetadata('auth_code');

        if (!$authCode instanceof AuthCode) {
            return;
        }

        if (array_key_exists('nonce', $params = $authCode->getQueryParams())) {
            $claims = array_merge(
                $claims,
                ['nonce' => $params['nonce']]
            );
        }

        $requested_claims = $this->getIdTokenClaims($accessToken);

        $dataTransporter = new DataTransporter();
        $command = CreateIdTokenCommand::create(
            $client,
            $user,
            $accessToken->getMetadata('redirect_uri'),
            $requested_claims,
            $accessToken->getMetadata('claims_locales'),
            $accessToken->getScopes(),
            $claims,
            $accessToken,
            $authCode,
            $dataTransporter
        );
        $this->commandBus->handle($command);

        /**
         * @var $data IdToken
         */
        $data = $dataTransporter->getData();
        foreach ($data->jsonSerialize() as $k => $v) {
            $grantTypeResponse = $grantTypeResponse->withParameter($k, $v);
        }
    }

    /**
     * @param AccessToken $accessToken
     *
     * @return array
     */
    private function getIdTokenClaims(AccessToken $accessToken)
    {
        if (!$accessToken->hasMetadata('requested_claims')) {
            return [];
        }

        $requested_claims = $accessToken->getMetadata('requested_claims');
        if (true === array_key_exists('id_token', $requested_claims)) {
            return $requested_claims['id_token'];
        }

        return [];
    }

    /**
     * @param GrantTypeResponse $grantTypeResponse
     *
     * @return bool
     */
    private function issueIdToken(GrantTypeResponse $grantTypeResponse)
    {
        return $grantTypeResponse->hasScope('openid');
    }

    /**
     * {@inheritdoc}
     */
    public function preAccessTokenCreation(Client $client, GrantTypeResponse $grantTypeResponse, array $tokenTypeInformation)
    {
        $data = [
            'redirect_uri' => $grantTypeResponse->getMetadata('redirect_uri'),
        ];
        if ($grantTypeResponse->hasMetadata('auth_code') && null !== $grantTypeResponse->getMetadata('auth_code')) {
            $data['claims_locales'] = array_key_exists('claims_locales', $grantTypeResponse->getMetadata('auth_code')->getQueryParams()) ? $grantTypeResponse->getMetadata('auth_code')->getQueryParams()['claims_locales'] : null;
            $data['requested_claims'] = array_key_exists('claims', $grantTypeResponse->getMetadata('auth_code')->getQueryParams()) ? $grantTypeResponse->getMetadata('auth_code')->getQueryParams()['claims'] : [];
        } else {
            $data['claims_locales'] = null;
            $data['requested_claims'] = [];
        }

        return $data;
    }
}
