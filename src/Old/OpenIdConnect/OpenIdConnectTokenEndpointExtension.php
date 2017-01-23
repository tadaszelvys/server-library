<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect;

use OAuth2\Command\IdToken\CreateIdTokenCommand;
use OAuth2\DataTransporter;
use OAuth2\Endpoint\Token\GrantTypeData;
use OAuth2\Endpoint\Token\TokenEndpointExtensionInterface;
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\IdToken\IdToken;
use OAuth2\Model\UserAccount\UserAccount;
use Psr\Http\Message\ServerRequestInterface;
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
     *
     * @param MessageBus $commandBus
     */
    public function __construct(MessageBus $commandBus)
    {
        $this->commandBus = $commandBus;
    }

    public function process(ServerRequestInterface $request, GrantTypeData $grantTypeData, callable $next): AccessToken
    {
        //pre

        $data = [
            'redirect_uri' => $grantTypeData->getMetadata('redirect_uri'),
        ];
        if ($grantTypeData->hasMetadata('auth_code') && null !== $grantTypeData->getMetadata('auth_code')) {
            $data['claims_locales'] = array_key_exists('claims_locales', $grantTypeData->getMetadata('auth_code')->getQueryParams()) ? $grantTypeData->getMetadata('auth_code')->getQueryParams()['claims_locales'] : null;
            $data['requested_claims'] = array_key_exists('claims', $grantTypeData->getMetadata('auth_code')->getQueryParams()) ? $grantTypeData->getMetadata('auth_code')->getQueryParams()['claims'] : [];
        } else {
            $data['claims_locales'] = null;
            $data['requested_claims'] = [];
        }

        return $data;

        //post
        /*if (true === $this->issueIdToken($grantTypeData) && $grantTypeData->hasMetadata('redirect_uri')) {
            $user = $grantTypeData->getResourceOwner();
            if (!$grantTypeData->getResourceOwner() instanceof UserAccount) {
                return;
            }

            $claims = [];
            $authCode = $grantTypeData->getMetadata('auth_code');

            if (!$authCode instanceof AuthCode) {
                return;
            }

            if (array_key_exists('nonce', $params = $authCode->getQueryParams())) {
                $claims = array_merge(
                    $claims,
                    ['nonce' => $params['nonce']]
                );
            }

            $requestedClaims = $this->getIdTokenClaims($accessToken);

            $dataTransporter = new DataTransporter();
            $command = CreateIdTokenCommand::create(
                $client,
                $user,
                $accessToken->getMetadata('redirect_uri'),
                $requestedClaims,
                $accessToken->getMetadata('claims_locales'),
                $accessToken->getScopes(),
                $claims,
                $accessToken,
                $authCode,
                $dataTransporter
            );
            $this->commandBus->handle($command);

            $data = $dataTransporter->getData();
            foreach ($data->jsonSerialize() as $k => $v) {
                $grantTypeData = $grantTypeData->withParameter($k, $v);
            }
        }*/
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

        $requestedClaims = $accessToken->getMetadata('requested_claims');
        if (true === array_key_exists('id_token', $requestedClaims)) {
            return $requestedClaims['id_token'];
        }

        return [];
    }

    /**
     * @param GrantTypeData $grantTypeData
     *
     * @return bool
     */
    private function issueIdToken(GrantTypeData $grantTypeData)
    {
        return $grantTypeData->hasScope('openid');
    }
}
