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

namespace OAuth2\Command\RefreshToken;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\UserAccount\UserAccountId;

final class CreateRefreshTokenCommand extends CommandWithDataTransporter
{
    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var UserAccountId
     */
    private $userAccountId;

    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var array
     */
    private $metadatas;

    /**
     * @var string[]
     */
    private $scopes;

    /**
     * CreateRefreshTokenCommand constructor.
     *
     * @param UserAccountId        $userAccountId
     * @param ClientId             $clientId
     * @param array                $parameters
     * @param \DateTimeImmutable   $expiresAt
     * @param array                $metadatas
     * @param string[]            $scopes
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(UserAccountId $userAccountId, ClientId $clientId, array $parameters, \DateTimeImmutable $expiresAt, array $metadatas, array $scopes, DataTransporter $dataTransporter = null)
    {
        $this->expiresAt = $expiresAt;
        $this->userAccountId = $userAccountId;
        $this->clientId = $clientId;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
        parent::__construct($dataTransporter);
    }

    /**
     * @param UserAccountId      $userAccountId
     * @param ClientId           $clientId
     * @param array              $parameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $metadatas
     * @param string[]          $scopes
     *
     * @return CreateRefreshTokenCommand
     */
    public static function create(UserAccountId $userAccountId, ClientId $clientId, array $parameters, \DateTimeImmutable $expiresAt, array $metadatas, array $scopes): self
    {
        return new self($userAccountId, $clientId, $parameters, $expiresAt, $metadatas, $scopes);
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /**
     * @return UserAccountId
     */
    public function getUserAccountId(): UserAccountId
    {
        return $this->userAccountId;
    }

    /**
     * @return ClientId
     */
    public function getClientId(): ClientId
    {
        return $this->clientId;
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

    /**
     * @return string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }
}
