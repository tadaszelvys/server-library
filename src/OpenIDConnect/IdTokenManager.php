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
use OAuth2\Client\Extension\TokenLifetimeExtensionInterface;
use OAuth2\OpenIDConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface;
use OAuth2\User\UserInterface as BaseUserInterface;
use Jose\JWTCreator;
use Jose\JWTLoader;

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
     * @var null|\OAuth2\OpenIDConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface
     */
    private $pairwise_algorithm = null;

    /**
     * IdTokenManager constructor.
     *
     * @param \Jose\JWTLoader    $jwt_loader
     * @param \Jose\JWTCreator   $jwt_creator
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
     * {@inheritdoc}
     */
    public function enablePairwiseSubject(PairwiseSubjectIdentifierAlgorithmInterface $pairwise_algorithm)
    {
        $this->pairwise_algorithm = $pairwise_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function isPairwiseSubjectIdentifierSupported()
    {
        return null !== $this->pairwise_algorithm;
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
    public function createIdToken(ClientInterface $client, BaseUserInterface $user, $redirect_uri, array $id_token_claims = [], $access_token = null, $auth_code = null)
    {
        $id_token = $this->createEmptyIdToken();
        $exp = time() + $this->getLifetime($client);

        $sub = $this->calculateSubjectIdentifier($client, $user, $redirect_uri);

        $headers = [
            'typ'       => 'JWT',
            'alg'       => $this->getSignatureAlgorithm(),
        ];

        $payload = [
            'jti'       => Base64Url::encode(random_bytes(25)),
            'iss'       => $this->issuer,
            'sub'       => $sub,
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

        $jwt = $this->jwt_creator->sign($payload, $headers, $this->signature_key);

        if ($client->hasPublicKeySet() && $client->has('id_token_encrypted_response_alg') && $client->has('id_token_encrypted_response_enc')) {
            $key_set = $client->getPublicKeySet();
            $key = $key_set->selectKey('enc');
            if (null !== $key) {
                $headers = [
                    'typ'       => 'JWT',
                    'jti'       => Base64Url::encode(random_bytes(25)),
                    'alg'       => $client->get('id_token_encrypted_response_alg'),
                    'enc'       => $client->get('id_token_encrypted_response_enc'),
                ];

                $jwt = $this->jwt_creator->encrypt(
                    $jwt,
                    $headers,
                    $key
                );
            }
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
     * @param \OAuth2\Client\ClientInterface $client
     * @param \OAuth2\User\UserInterface     $user
     * @param string                         $redirect_uri
     *
     * @return string
     */
    private function calculateSubjectIdentifier(ClientInterface $client, BaseUserInterface $user, $redirect_uri)
    {
        $sub = $user->getPublicId();

        if (false === $this->isPairwiseSubjectIdentifierSupported()) {
            return $sub;
        }

        $sector_identifier_host = $this->getSectorIdentifierHost($client, $redirect_uri);

        return $this->pairwise_algorithm->calculateSubjectIdentifier(
            $user,
            $sector_identifier_host
        );
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $redirect_uri
     *
     * @return string
     */
    private function getSectorIdentifierHost(ClientInterface $client, $redirect_uri)
    {
        $uri = $redirect_uri;

        if (true === $client->has('sector_identifier_uri')) {
            $uri = $client->get('sector_identifier_uri');
        }

        $data = parse_url($uri);
        if (!is_array($data) || !array_key_exists('host', $data)) {
            throw new \InvalidArgumentException(sprintf('Invalid Sector Identifier Uri "%s".', $uri));
        }

        return $data['host'];
    }

    /**
     * @param string $token
     *
     * @return string
     */
    private function getHash($token)
    {
        return Base64Url::encode(mb_substr(hash($this->getHashMethod(), $token, true), 0, $this->getHashSize(), '8bit'));
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function getHashMethod()
    {
        $map = [
            'HS256' => 'sha256',
            'ES256' => 'sha256',
            'RS256' => 'sha256',
            'PS256' => 'sha256',
            'HS384' => 'sha384',
            'ES384' => 'sha384',
            'RS384' => 'sha384',
            'PS384' => 'sha384',
            'HS512' => 'sha512',
            'ES512' => 'sha512',
            'RS512' => 'sha512',
            'PS512' => 'sha512',
        ];

        if (array_key_exists($this->signature_algorithm, $map)) {
            return $map[$this->signature_algorithm];
        }

        throw new \InvalidArgumentException(sprintf('Algorithm "%s" is not supported', $this->signature_algorithm));
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getHashSize()
    {
        $map = [
            'HS256' => 16,
            'ES256' => 16,
            'RS256' => 16,
            'PS256' => 16,
            'HS384' => 24,
            'ES384' => 24,
            'RS384' => 24,
            'PS384' => 24,
            'HS512' => 32,
            'ES512' => 32,
            'RS512' => 32,
            'PS512' => 32,
        ];

        if (array_key_exists($this->signature_algorithm, $map)) {
            return $map[$this->signature_algorithm];
        }
        throw new \InvalidArgumentException(sprintf('Algorithm "%s" is not supported', $this->signature_algorithm));
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
