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

namespace OAuth2\Command\AuthCode;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\UserAccount\UserAccountId;
use Psr\Http\Message\UriInterface;

final class CreateAuthCodeCommand extends CommandWithDataTransporter
{
    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var UserAccountId
     */
    private $userAccountId;

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
     * @var UriInterface
     */
    private $redirectUri;

    /**
     * CreateAuthCodeCommand constructor.
     *
     * @param ClientId             $clientId
     * @param UserAccountId        $userAccountId
     * @param array                $queryParameters
     * @param UriInterface         $redirectUri
     * @param \DateTimeImmutable   $expiresAt
     * @param array                $parameters
     * @param array                $scopes
     * @param array                $metadatas
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas, DataTransporter $dataTransporter = null)
    {
        $this->clientId = $clientId;
        $this->userAccountId = $userAccountId;
        $this->queryParameters = $queryParameters;
        $this->expiresAt = $expiresAt;
        $this->redirectUri = $redirectUri;
        $this->parameters = $parameters;
        $this->scopes = $scopes;
        $this->metadatas = $metadatas;
        parent::__construct($dataTransporter);
    }

    /**
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param array              $queryParameters
     * @param UriInterface       $redirectUri
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return CreateAuthCodeCommand
     */
    public static function create(ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas): self
    {
        return new self($clientId, $userAccountId, $queryParameters, $redirectUri, $expiresAt, $parameters, $scopes, $metadatas);
    }

    /**
     * @return ClientId
     */
    public function getClientId(): ClientId
    {
        return $this->clientId;
    }

    /**
     * @return UserAccountId
     */
    public function getUserAccountId(): UserAccountId
    {
        return $this->userAccountId;
    }

    /**
     * @return array
     */
    public function getQueryParameters(): array
    {
        return $this->queryParameters;
    }

    /**
     * @return UriInterface
     */
    public function getRedirectUri(): UriInterface
    {
        return $this->redirectUri;
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
