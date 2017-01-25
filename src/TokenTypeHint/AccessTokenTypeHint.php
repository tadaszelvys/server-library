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

namespace OAuth2\TokenTypeHint;

use OAuth2\Command\AccessToken\RevokeAccessTokenCommand;
use OAuth2\Model\AccessToken\AccessTokenId;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Model\Token\TokenId;
use SimpleBus\Message\Bus\MessageBus;

final class AccessTokenTypeHint implements TokenTypeHintInterface
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * AccessToken constructor.
     *
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param MessageBus                     $commandBus
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, MessageBus $commandBus)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->commandBus = $commandBus;
    }

    /**
     * {@inheritdoc}
     */
    public function hint(): string
    {
        return 'access_token';
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $token)
    {
        $id = AccessTokenId::create($token);

        return $this->accessTokenRepository->find($id);
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(TokenId $tokenId)
    {
        if (!$tokenId instanceof AccessTokenId) {
            return;
        }
        $revokeAccessTokenCommand = RevokeAccessTokenCommand::create($tokenId);
        $this->commandBus->handle($revokeAccessTokenCommand);
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(TokenId $tokenId): array
    {
        if (!$tokenId instanceof AccessTokenId || !$this->accessTokenRepository->has($tokenId)) {
            return [
                'active' => false,
            ];
        }

        $accessToken = $this->accessTokenRepository->find($tokenId);

        $values = [
            'active'         => !$accessToken->hasExpired(),
            'client_id'      => $accessToken->getClientId(),
            'resource_owner' => $accessToken->getResourceOwnerId(),
            'expires_in'     => $accessToken->getExpiresIn(),
        ];
        if (!empty($accessToken->getScopes())) {
            $values['scope'] = implode(' ', $accessToken->getScopes());
        }

        return $values + $accessToken->getParameters();
    }
}
