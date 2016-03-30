<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Object\JWKInterface;
use OAuth2\Behaviour\HasJWTCreator;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\EncryptionCapabilitiesInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\User\UserInterface as BaseUserInterface;
use OAuth2\Util\JWTCreator;
use OAuth2\Util\JWTLoader;

class IdTokenManager implements IdTokenManagerInterface
{
    use HasJWTCreator;
    use HasJWTLoader;

    /**
     * @var int
     */
    private $id_token_lifetime = 3600;

    /**
     * @var string
     */
    private $issuer;

    /**
     * @var string
     */
    private $signature_algorithm;

    /**
     * @var \Jose\Object\JWKInterface
     */
    private $signature_key;

    /**
     * @var \OAuth2\OpenIDConnect\IdTokenClaimManagerInterface[]
     */
    private $id_token_claim_managers = [];

    /**
     * IdTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader    $jwt_loader
     * @param \OAuth2\Util\JWTCreator   $jwt_creator
     * @param                           $issuer
     * @param                           $signature_algorithm
     * @param \Jose\Object\JWKInterface $signature_key
     */
    public function __construct(JWTLoader $jwt_loader,
                                JWTCreator $jwt_creator,
                                $issuer,
                                $signature_algorithm,
                                JWKInterface $signature_key
    ) {
        Assertion::string($signature_algorithm);
        Assertion::string($issuer);
        $this->issuer = $issuer;
        $this->signature_algorithm = $signature_algorithm;
        $this->signature_key = $signature_key;

        $this->setJWTLoader($jwt_loader);
        $this->setJWTCreator($jwt_creator);
    }

    /**
     * @param \OAuth2\OpenIDConnect\IdTokenClaimManagerInterface $id_token_claim_manager
     */
    public function addIdTokenClaimManager(IdTokenClaimManagerInterface $id_token_claim_manager)
    {
        $this->id_token_claim_managers[] = $id_token_claim_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatureAlgorithms()
    {
        return $this->getJWTLoader()->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyEncryptionAlgorithms()
    {
        return $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getContentEncryptionAlgorithms()
    {
        return $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function createIdToken(ClientInterface $client, BaseUserInterface $user, array $id_token_claims = [], $access_token = null, $auth_code = null)
    {
        $id_token = $this->createEmptyIdToken();
        $exp = time() + $this->getLifetime($client);

        $headers = [
            'typ'       => 'JWT',
            'alg'       => $this->getSignatureAlgorithm(),
        ];

        $payload = [
            'jti'       => Base64Url::encode(random_bytes(25)),
            'iss'       => $this->issuer,
            'sub'       => $user->getPublicId(),
            'aud'       => $client->getPublicId(),
            'iat'       => time(),
            'nbf'       => time(),
            'exp'       => $exp,
        ];
        if ($user instanceof UserInterface) {

            $payload['auth_time'] = $user->getLastLoginAt();
        }

        foreach (['at_hash' => $access_token, 'c_hash' => $auth_code] as $key => $token) {
            if (null !== $token) {
                $payload[$key] = $this->getHash($token);
            }
        }
        foreach (['amr' => 'getAuthenticationMethodsReferences', 'acr' => 'getAuthenticationContextClassReference'] as $claims => $method) {
            $value = $user->$method();
            if (!empty($value)) {
                $payload[$claims] = $value;
            }
        }

        if (!empty($id_token_claims)) {
            $payload = array_merge($payload, $id_token_claims);
        }

        foreach ($this->id_token_claim_managers as $id_token_claim_manager) {
            $id_token_claim_manager->process($payload, $headers, $user, $client);
        }
        
        $jwt = $this->jwt_creator->sign($payload, $headers, $this->signature_key);
        
        if ($client instanceof EncryptionCapabilitiesInterface && true === $client->isEncryptionSupportEnabled()) {
            $headers = [
                'typ'       => 'JWT',
                'jti'       => Base64Url::encode(random_bytes(25)),
                'alg'       => $client->getKeyEncryptionAlgorithm(),
                'enc'       => $client->getContentEncryptionAlgorithm(),
            ];

            $jwt = $this->jwt_creator->encrypt(
                $jwt,
                $headers,
                $client->getEncryptionPublicKey()
            );
        }
        $id_token->setToken($jwt);

        $id_token->setExpiresAt($exp);
        $id_token->setClientPublicId($client->getPublicId());
        $id_token->setResourceOwnerPublicId($user->getPublicId());

        return $id_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeIdToken(IdTokenInterface $token)
    {
        //Not supported
    }

    /**
     * @return \OAuth2\OpenIDConnect\IdTokenInterface
     */
    protected function createEmptyIdToken()
    {
        return new IdToken();
    }

    /**
     * @param string $token
     *
     * @return string
     */
    private function getHash($token)
    {
        return Base64Url::encode(substr(hash($this->getHashMethod(), $token, true), 0, $this->getHashSize()));
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function getHashMethod()
    {
        switch ($this->signature_algorithm) {
            case 'HS256':
            case 'ES256':
            case 'RS256':
            case 'PS256':
                return 'sha256';
            case 'HS384':
            case 'ES384':
            case 'RS384':
            case 'PS384':
                return 'sha384';
            case 'HS512':
            case 'ES512':
            case 'RS512':
            case 'PS512':
                return 'sha512';
            default:
                throw new \InvalidArgumentException(sprintf('Algorithm "%s" is not supported', $this->signature_algorithm));
        }
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getHashSize()
    {
        switch ($this->signature_algorithm) {
            case 'HS256':
            case 'ES256':
            case 'RS256':
            case 'PS256':
                return 128 / 8;
            case 'HS384':
            case 'ES384':
            case 'RS384':
            case 'PS384':
                return 192 / 8;
            case 'HS512':
            case 'ES512':
            case 'RS512':
            case 'PS512':
                return 256 / 8;
            default:
                throw new \InvalidArgumentException(sprintf('Algorithm "%s" is not supported', $this->signature_algorithm));
        }
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    private function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getIdTokenLifetime();
        if ($client instanceof TokenLifetimeExtensionInterface && is_int($_lifetime = $client->getTokenLifetime('id_token'))) {
            return $_lifetime;
        }

        return $lifetime;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function getSignatureAlgorithm()
    {
        return $this->signature_algorithm;
    }

    /**
     * @return int
     */
    public function getIdTokenLifetime()
    {
        return $this->id_token_lifetime;
    }

    /**
     * @param int $id_token_lifetime
     */
    public function setIdTokenLifetime($id_token_lifetime)
    {
        Assertion::integer($id_token_lifetime);
        Assertion::greaterThan($id_token_lifetime, 0);
        $this->id_token_lifetime = $id_token_lifetime;
    }
}
