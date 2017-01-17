<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Model\InitialAccessToken\InitialAccessToken;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenId;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountId;
use Ramsey\Uuid\Uuid;

class InitialAccessTokenRepository implements InitialAccessTokenRepositoryInterface
{
    /**
     * @var InitialAccessToken[]
     */
    private $initialAccessTokens = [];

    /**
     * {@inheritdoc}
     */
    public function create(UserAccount $userAccount, \DateTimeImmutable $expiresAt = null)
    {
        $initialAccessTokeId = InitialAccessTokenId::create(Uuid::uuid4()->toString());

        return InitialAccessToken::create($initialAccessTokeId, $userAccount, $expiresAt);
    }

    /**
     * InitialAccessTokenManager constructor.
     */
    public function __construct()
    {
        $valid_initialAccessToken = InitialAccessToken::create(
            InitialAccessTokenId::create('INITIAL_ACCESS_TOKEN_VALID'),
            UserAccount::create(UserAccountId::create('user1'), []),
            new \DateTimeImmutable('now +1 hour')
        );
        $this->save($valid_initialAccessToken);

        $expired_initialAccessToken = InitialAccessToken::create(
            InitialAccessTokenId::create('INITIAL_ACCESS_TOKEN_EXPIRED'),
            UserAccount::create(UserAccountId::create('user1'), []),
            new \DateTimeImmutable('now -1 hour')
        );
        $this->save($expired_initialAccessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function save(InitialAccessToken $initialAccessToken)
    {
        $this->initialAccessTokens[(string) $initialAccessToken->getId()] = $initialAccessToken;
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(InitialAccessToken $initialAccessToken)
    {
        if (isset($this->initialAccessTokens[(string) $initialAccessToken->getId()])) {
            unset($this->initialAccessTokens[(string) $initialAccessToken->getId()]);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function find(InitialAccessTokenId $initialAccessTokenId)
    {
        return array_key_exists((string) $initialAccessTokenId, $this->initialAccessTokens) ? $this->initialAccessTokens[(string) $initialAccessTokenId] : null;
    }
}
