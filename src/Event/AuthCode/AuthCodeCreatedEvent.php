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

namespace OAuth2\Event\AuthCode;

use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Event\Event;
use OAuth2\Model\UserAccount\UserAccountId;
use Psr\Http\Message\UriInterface;

final class AuthCodeCreatedEvent extends Event
{
    /**
     * @var AuthCodeId
     */
    private $authCodeId;

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
     * @var array
     */
    private $queryParameters;

    /**
     * @var UriInterface
     */
    private $redirectUri;

    /**
     * AuthCodeCreatedEvent constructor.
     *
     * @param AuthCodeId         $authCodeId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param array              $queryParameters
     * @param UriInterface       $redirectUri
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     */
    protected function __construct(AuthCodeId $authCodeId, ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        parent::__construct();
        $this->authCodeId = $authCodeId;
        $this->userAccountId = $userAccountId;
        $this->clientId = $clientId;
        $this->expiresAt = $expiresAt;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
        $this->redirectUri = $redirectUri;
        $this->queryParameters = $queryParameters;
    }

    /**
     * @param AuthCodeId         $authCodeId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param array              $queryParameters
     * @param UriInterface       $redirectUri
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return self
     */
    public static function create(AuthCodeId $authCodeId, ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas): self
    {
        return new self($authCodeId, $clientId, $userAccountId, $queryParameters, $redirectUri, $expiresAt, $parameters, $scopes, $metadatas);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'auth_code_id'     => $this->authCodeId,
            'user_account_id'  => $this->userAccountId,
            'client_id'        => $this->clientId,
            'expires_at'       => $this->expiresAt->getTimestamp(),
            'parameters'       => $this->parameters,
            'metadatas'        => $this->metadatas,
            'scopes'           => $this->scopes,
            'redirect_uri'     => $this->redirectUri,
            'query_parameters' => $this->queryParameters,
        ];
    }
}
