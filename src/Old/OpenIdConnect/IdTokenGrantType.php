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
use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Grant\ResponseTypeInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\UriInterface;
use SimpleBus\Message\Bus\MessageBus;

class IdTokenGrantType implements ResponseTypeInterface
{
    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * IdTokenGrantType constructor.
     * @param MessageBus $commandBus
     */
    public function __construct(MessageBus $commandBus)
    {
        $this->commandBus = $commandBus;
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedGrantTypes(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType(): string
    {
        return 'id_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode(): string
    {
        return self::RESPONSE_TYPE_MODE_FRAGMENT;
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAuthorization(Authorization $authorization)
    {
        if (!in_array('openid', $authorization->getScopes())) {
            return [];
        }
        if (!array_key_exists('nonce', $authorization->getQueryParams())) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => 'The parameter \'nonce\' is mandatory using \'id_token\' response type.',
                ]
            );
        }

        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, UriInterface $redirectUri)
    {
        $params = $authorization->getQueryParams();
        $requested_claims = $this->getIdTokenClaims($authorization);
        $dataTransporter = new DataTransporter();
        $command = CreateIdTokenCommand::create(
            $authorization->getClient(),
            $authorization->getUserAccount(),
            $redirectUri,
            $authorization->hasQueryParam('claims_locales') ? $authorization->getQueryParam('claims_locales') : null,
            $requested_claims,
            $authorization->getScopes(),
            ['nonce' => $params['nonce']],
            $authorization->hasData('access_token') ? $authorization->getData('access_token') : null,
            $authorization->hasData('code') ? $authorization->getData('code') : null,
            $dataTransporter
        );
        $this->commandBus->handle($command);
        $authorization = $authorization->withData('id_token', $dataTransporter->getData());
        $response_parameters = $response_parameters + $dataTransporter->getData()->toArray();
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\Authorization $authorization
     *
     * @return array
     */
    private function getIdTokenClaims(Authorization $authorization): array
    {
        if (!$authorization->hasQueryParam('claims')) {
            return [];
        }

        $requested_claims = $authorization->getQueryParam('claims');
        if (true === array_key_exists('id_token', $requested_claims)) {
            return $requested_claims['id_token'];
        }

        return [];
    }
}
