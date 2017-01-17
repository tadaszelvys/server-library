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

namespace OAuth2\Command\AuthCode;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;

final class CreateAuthCodeCommand extends CommandWithDataTransporter
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var UserAccount
     */
    private $userAccount;

    /**
     * @var array
     */
    private $queryParameters;

    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var array
     */
    private $scopes;

    /**
     * @var array
     */
    private $metadatas;

    /**
     * CreateAuthCodeCommand constructor.
     *
     * @param Client               $client
     * @param UserAccount          $userAccount
     * @param array                $queryParameters
     * @param \DateTimeImmutable   $expiresAt
     * @param array                $parameters
     * @param array                $scopes
     * @param array                $metadatas
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(Client $client, UserAccount $userAccount, array $queryParameters, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas, DataTransporter $dataTransporter = null)
    {
        $this->client = $client;
        $this->userAccount = $userAccount;
        $this->queryParameters = $queryParameters;
        $this->expiresAt = $expiresAt;
        $this->parameters = $parameters;
        $this->scopes = $scopes;
        $this->metadatas = $metadatas;
        parent::__construct($dataTransporter);
    }

    /**
     * @param Client             $client
     * @param UserAccount        $userAccount
     * @param array              $queryParameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return CreateAuthCodeCommand
     */
    public static function create(Client $client, UserAccount $userAccount, array $queryParameters, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas): self
    {
        return new self($client, $userAccount, $queryParameters, $expiresAt, $parameters, $scopes, $metadatas);
    }

    /**
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }

    /**
     * @return UserAccount
     */
    public function getUserAccount(): UserAccount
    {
        return $this->userAccount;
    }

    /**
     * @return array
     */
    public function getQueryParameters(): array
    {
        return $this->queryParameters;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
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
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return array
     */
    public function getMetadatas(): array
    {
        return $this->metadatas;
    }
}
