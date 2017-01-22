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

use Assert\Assertion;
use OAuth2\Command\AuthCode\RevokeAuthCodeCommand;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Token\Token;
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
        return $this->authorizationCodeRepository->find(AuthCodeId::create($token));
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(Token $token)
    {
        if (!$token instanceof AuthCode) {
            return;
        }
        $revokeAuthCodeCommand = RevokeAuthCodeCommand::create($token);
        $this->commandBus->handle($revokeAuthCodeCommand);
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(Token $token): array
    {
        Assertion::isInstanceOf($token, AuthCode::class);

        $result = [
            'active'     => !$token->hasExpired(),
            'client_id'  => $token->getClient()->getId(),
            'exp'        => $token->getExpiresAt()->getTimestamp(),
        ];

        if (!empty($token->getScopes())) {
            $result['scp'] = $token->getScopes();
        }

        return $result;
    }
}
