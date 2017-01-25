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

namespace OAuth2\Model\Client;

use Assert\Assertion;
use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use OAuth2\Event\Client\ClientCreatedEvent;
use OAuth2\Event\Client\ClientParameterRemovedEvent;
use OAuth2\Event\Client\ClientParametersUpdatedEvent;
use OAuth2\Event\Client\ClientParameterUpdatedEvent;
use OAuth2\Model\ResourceOwner\ResourceOwner;
use OAuth2\Model\UserAccount\UserAccountId;

/**
 * Class Client.
 *
 * This class is used for every client types.
 * A client is a resource owner with a set of allowed grant types and can perform requests against
 * available endpoints.
 */
final class Client extends ResourceOwner
{
    /**
     * @var UserAccountId
     */
    private $userAccountId = null;

    /**
     * Client constructor.
     *
     * @param ClientId      $id
     * @param array         $parameter
     * @param UserAccountId $userAccountId
     */
    protected function __construct(ClientId $id, array $parameter, UserAccountId $userAccountId)
    {
        parent::__construct($id, $parameter);
        $this->userAccountId = $userAccountId;

        $event = ClientCreatedEvent::create($id, $parameter, $userAccountId);
        $this->record($event);
    }

    /**
     * @param ClientId      $id
     * @param array         $parameter
     * @param UserAccountId $userAccountId
     *
     * @return self
     */
    public static function create(ClientId $id, array $parameter, UserAccountId $userAccountId): self
    {
        return new self($id, $parameter, $userAccountId);
    }

    /**
     * @return UserAccountId
     */
    public function getResourceOwnerId(): UserAccountId
    {
        return $this->userAccountId;
    }

    /**
     * @param array $parameters
     *
     * @return Client
     */
    public function withParameters(array $parameters): self
    {
        $clone = clone $this;
        $clone->parameters = $parameters;
        $event = ClientParametersUpdatedEvent::create($clone->getId(), $parameters);
        $clone->record($event);

        return $clone;
    }

    /**
     * @param string     $key
     * @param mixed|null $value
     *
     * @return Client
     */
    public function withParameter(string $key, $value): self
    {
        $clone = clone $this;
        $clone->parameters[$key] = $value;
        $event = ClientParameterUpdatedEvent::create($clone->getId(), $key, $value);
        $clone->record($event);

        return $clone;
    }

    /**
     * @param string $key
     *
     * @return Client
     */
    public function withoutParameter(string $key): self
    {
        if (!$this->has($key)) {
            return $this;
        }
        $clone = clone $this;
        unset($clone->parameters[$key]);
        $event = ClientParameterRemovedEvent::create($clone->getId(), $key);
        $clone->record($event);

        return $clone;
    }

    /**
     * @param string $grant_type
     *
     * @return bool
     */
    public function isGrantTypeAllowed(string $grant_type): bool
    {
        Assertion::string($grant_type, 'Argument must be a string.');
        $grant_types = $this->has('grant_types') ? $this->get('grant_types') : [];
        Assertion::isArray($grant_types, 'The metadata \'grant_types\' must be an array.');

        return in_array($grant_type, $grant_types);
    }

    /**
     * @param string $response_type
     *
     * @return bool
     */
    public function isResponseTypeAllowed(string $response_type): bool
    {
        Assertion::string($response_type, 'Argument must be a string.');
        $response_types = $this->has('response_types') ? $this->get('response_types') : [];
        Assertion::isArray($response_types, 'The metadata \'response_types\' must be an array.');

        return in_array($response_type, $response_types);
    }

    /**
     * @param string $token_type
     *
     * @return bool
     */
    public function isTokenTypeAllowed(string $token_type): bool
    {
        Assertion::string($token_type, 'Argument must be a string.');
        if (!$this->has('token_types')) {
            return true;
        }
        $token_types = $this->get('token_types');
        Assertion::isArray($token_types, 'The metadata \'token_types\' must be an array.');

        return in_array($token_type, $token_types);
    }

    /**
     * @return bool
     */
    public function isPublic(): bool
    {
        return 'none' === $this->getTokenEndpointAuthMethod();
    }

    /**
     * @return string
     */
    public function getTokenEndpointAuthMethod(): string
    {
        if ($this->has('token_endpoint_auth_method')) {
            return $this->get('token_endpoint_auth_method');
        }

        return 'client_secret_basic';
    }

    /**
     * @return int
     */
    public function getClientSecretExpiresAt(): int
    {
        if ($this->has('client_secret_expires_at')) {
            return $this->get('client_secret_expires_at');
        }

        return 0;
    }

    /**
     * @return bool
     */
    public function areClientCredentialsExpired(): bool
    {
        if (0 === $this->getClientSecretExpiresAt()) {
            return false;
        }

        return time() > $this->getClientSecretExpiresAt();
    }

    /**
     * @return bool
     */
    public function hasPublicKeySet(): bool
    {
        return $this->has('jwks') || $this->has('jwks_uri') || $this->has('client_secret');
    }

    /**
     * @return JWKSetInterface
     */
    public function getPublicKeySet(): JWKSetInterface
    {
        Assertion::true($this->hasPublicKeySet(), 'The client has no public key set');

        if ($this->has('jwks')) {
            return new JWKSet($this->get('jwks'));
        }
        if ($this->has('jwks_uri')) {
            return JWKFactory::createFromJKU($this->get('jwks_uri'));
        }
        if ($this->has('client_secret')) {
            $jwk_set = new JWKSet();
            $jwk_set->addKey(new JWK([
                'kty' => 'oct',
                'use' => 'sig',
                'k'   => $this->get('client_secret'),
            ]));

            return $jwk_set;
        }
    }
}
