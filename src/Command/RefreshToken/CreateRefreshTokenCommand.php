<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\RefreshToken;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;

final class CreateRefreshTokenCommand extends CommandWithDataTransporter
{
    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var UserAccount
     */
    private $userAccount;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var array
     */
    private $metadatas;

    /**
     * CreateRefreshTokenCommand constructor.
     * @param UserAccount $userAccount
     * @param Client $client
     * @param array $parameters
     * @param \DateTimeImmutable $expiresAt
     * @param array $metadatas
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(UserAccount $userAccount, Client $client, array $parameters, \DateTimeImmutable $expiresAt, array $metadatas, DataTransporter $dataTransporter = null)
    {
        $this->expiresAt = $expiresAt;
        $this->userAccount = $userAccount;
        $this->client = $client;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        parent::__construct($dataTransporter);
    }

    /**
     * @param UserAccount        $userAccount
     * @param Client             $client
     * @param array              $parameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $metadatas
     *
     * @return CreateRefreshTokenCommand
     */
    public static function create(UserAccount $userAccount, Client $client, array $parameters, \DateTimeImmutable $expiresAt, array $metadatas): self
    {
        return new self($userAccount, $client, $parameters, $expiresAt, $metadatas);
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /**
     * @return UserAccount
     */
    public function getUserAccount(): UserAccount
    {
        return $this->userAccount;
    }

    /**
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }

    /**
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * @return array
     */
    public function getMetadatas(): array
    {
        return $this->metadatas;
    }
}
