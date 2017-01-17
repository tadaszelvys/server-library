<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseType;

use OAuth2\Command\AccessToken\CreateAccessTokenCommand;
use OAuth2\DataTransporter;
use OAuth2\Endpoint\Authorization\Authorization;
use Psr\Http\Message\UriInterface;
use SimpleBus\Message\Bus\MessageBus;

class ImplicitResponseType implements ResponseTypeInterface
{
    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * ImplicitGrantType constructor.
     *
     * @param MessageBus $messageBus
     */
    public function __construct(MessageBus $messageBus)
    {
        $this->messageBus = $messageBus;
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
        return 'token';
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
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, UriInterface $redirect_uri)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAuthorization(Authorization $authorization): array
    {
        $tokenType = $authorization->getTokenType();

        $dataTransporter = new DataTransporter();
        $command = CreateAccessTokenCommand::create(
            $authorization->getClient(),
            $authorization->getUserAccount(),
            $tokenType->getTokenTypeInformation(),
            $authorization->getQueryParams(),
            $authorization->getScopes(),
            null, // Refresh token
            null, // Resource Server
            ['redirect_uri' => $authorization->getRedirectUri()],
            $dataTransporter
        );

        $this->commandBus->handle($command);
        $authorization = $authorization->withData('access_token', $dataTransporter->getData());

        return $dataTransporter->getData()->toArray();
    }
}
