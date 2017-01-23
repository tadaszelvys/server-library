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

use OAuth2\Command\AuthCode\RevokeAuthCodeCommand;
use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Token\TokenId;
use SimpleBus\Message\Bus\MessageBus;

class AuthCodeTypeHint implements TokenTypeHintInterface
{
    /**
     * @var AuthCodeRepositoryInterface
     */
    private $authorizationCodeRepository;

    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * AuthCode constructor.
     *
     * @param AuthCodeRepositoryInterface $authorizationCodeRepository
     * @param MessageBus                  $commandBus
     */
    public function __construct(AuthCodeRepositoryInterface $authorizationCodeRepository, MessageBus $commandBus)
    {
        $this->authorizationCodeRepository = $authorizationCodeRepository;
        $this->commandBus = $commandBus;
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHint(): string
    {
        return 'auth_code';
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $token)
    {
        $id = AuthCodeId::create($token);

        return $this->authorizationCodeRepository->find($id);
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(TokenId $tokenId)
    {
        if (!$tokenId instanceof AuthCodeId) {
            return;
        }
        $revokeAuthCodeCommand = RevokeAuthCodeCommand::create($tokenId);
        $this->commandBus->handle($revokeAuthCodeCommand);
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(TokenId $tokenId): array
    {
        if (!$tokenId instanceof AuthCodeId || !$this->authorizationCodeRepository->has($tokenId)) {
            return [
                'active' => false,
            ];
        }

        $authCode = $this->authorizationCodeRepository->find($tokenId);

        $result = [
            'active'     => !$authCode->hasExpired(),
            'client_id'  => $authCode->getClientId(),
            'exp'        => $authCode->getExpiresAt()->getTimestamp(),
        ];

        if (!empty($authCode->getScopes())) {
            $result['scp'] = $authCode->getScopes();
        }

        return $result;
    }
}
