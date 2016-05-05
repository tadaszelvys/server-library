<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\JWTCreator;
use Jose\JWTLoader;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use OAuth2\Behaviour\HasJWTCreator;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

class JWTAccessTokenManager extends AccessTokenManager
{
    use HasJWTLoader;
    use HasJWTCreator;

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
     * @var string|null
     */
    private $key_encryption_algorithm = null;

    /**
     * @var string|null
     */
    private $content_encryption_algorithm = null;

    /**
     * @var \Jose\Object\JWKInterface|null
     */
    private $key_encryption_key = null;

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \Jose\JWTCreator          $jwt_creator
     * @param \Jose\JWTLoader           $jwt_loader
     * @param string                    $signature_algorithm
     * @param \Jose\Object\JWKInterface $signature_key
     * @param string                    $issuer
     */
    public function __construct(JWTCreator $jwt_creator,
                                JWTLoader $jwt_loader,
                                $signature_algorithm,
                                JWKInterface $signature_key,
                                $issuer
    ) {
        Assertion::inArray($signature_algorithm, $jwt_creator->getSupportedSignatureAlgorithms());
        Assertion::string($issuer);

        $this->signature_algorithm = $signature_algorithm;
        $this->signature_key = $signature_key;
        $this->issuer = $issuer;

        $this->setJWTCreator($jwt_creator);
        $this->setJWTLoader($jwt_loader);
    }

    /**
     * @param string                    $key_encryption_algorithm
     * @param string                    $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface $key_encryption_key
     */
    public function enableAccessTokenEncryption($key_encryption_algorithm,
                                                $content_encryption_algorithm,
                                                JWKInterface $key_encryption_key
    ) {
        Assertion::inArray($key_encryption_algorithm, $this->jwt_creator->getSupportedKeyEncryptionAlgorithms());
        Assertion::inArray($content_encryption_algorithm, $this->jwt_creator->getSupportedContentEncryptionAlgorithms());

        $this->key_encryption_algorithm = $key_encryption_algorithm;
        $this->content_encryption_algorithm = $content_encryption_algorithm;
        $this->key_encryption_key = $key_encryption_key;
    }

    /**
     * {@inheritdoc}
     */
    public function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null, ClientInterface $resource_server = null)
    {
        $payload = $this->preparePayload($access_token, $resource_server);
        $signature_header = $this->prepareSignatureHeader();

        $jwt = $this->getJWTCreator()->sign($payload, $signature_header, $this->signature_key);

        if ($this->isEncryptionEnabled()) {
            $encryption_header = $this->prepareEncryptionHeader($client, $resource_server);
            $recipient_key = $this->key_encryption_key;

            $jwt = $this->getJWTCreator()->encrypt($jwt, $encryption_header, $recipient_key);
        }

        $access_token->setToken($jwt);
    }

    /**
     * @param \OAuth2\Client\ClientInterface       $client
     * @param \OAuth2\Client\ClientInterface|null $resource_server
     *
     * @return array
     */
    protected function prepareEncryptionHeader(ClientInterface $client, ClientInterface $resource_server = null)
    {
        $key_encryption_algorithm = $this->key_encryption_algorithm;
        $content_encryption_algorithm = $this->content_encryption_algorithm;
        $header = array_merge(
            [
                'jti' => Base64Url::encode(random_bytes(25)),
                'iss' => $this->issuer,
                'iat' => time(),
                'nbf' => time(),
                'typ' => 'JWT',
                'alg' => $key_encryption_algorithm,
                'enc' => $content_encryption_algorithm,
            ]
        );
        if (0 !== $lifetime = $this->getLifetime($client)) {
            $header['exp'] = time() + $lifetime;
        }
        $header['aud'] = null === $resource_server ? $this->issuer : $resource_server->getPublicId();

        return $header;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function prepareSignatureHeader()
    {
        $header = [
            'typ' => 'JWT',
            'alg' => $this->signature_algorithm,
        ];

        return $header;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface  $access_token
     * @param \OAuth2\Client\ClientInterface|null $resource_server
     *
     * @return array
     */
    protected function preparePayload(AccessTokenInterface $access_token, ClientInterface $resource_server = null)
    {
        $payload = [
            'jti'            => Base64Url::encode(random_bytes(25)),
            'iss'            => $this->issuer,
            'aud'            => null === $resource_server ? $this->issuer : $resource_server->getPublicId(),
            'iat'            => time(),
            'nbf'            => time(),
            'exp'            => $access_token->getExpiresAt(),
            'sub'            => $access_token->getClientPublicId(),
            'token_type'     => $access_token->getTokenType(),
            'scp'            => $access_token->getScope(),
            'resource_owner' => $access_token->getResourceOwnerPublicId(),
        ];
        $payload['metadatas'] = $access_token->getMetadatas();
        if (0 !== $expires_at = $access_token->getExpiresAt()) {
            $payload['exp'] = $expires_at;
        }
        if (!empty($access_token->getParameters())) {
            $parameters = $access_token->getParameters();
            //This part should be updated to support 'cnf' (confirmation) claim (see POP).

            $payload['other'] = $parameters;
        }
        if (null !== $access_token->getRefreshToken()) {
            $payload['refresh_token'] = $access_token->getRefreshToken();
        }

        return $payload;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($assertion)
    {
        try {
            $jwk_set = new JWKSet();
            if (true === $this->isEncryptionEnabled()) {
                $jwk_set->addKey($this->key_encryption_key);
            }
            $jwt = $this->getJWTLoader()->load(
                $assertion,
                $jwk_set,
                $this->isEncryptionEnabled()
            );

            $jwk_set = new JWKSet();
            $jwk_set->addKey($this->signature_key);
            $this->jwt_loader->verifySignature($jwt, $jwk_set);
        } catch (\Exception $e) {
            return;
        }

        $access_token = new JWTAccessToken();
        $access_token->setToken($assertion);
        $access_token->setJWS($jwt);
        $access_token->setClientPublicId($jwt->getClaim('sub'));
        $access_token->setTokenType($jwt->getClaim('token_type'));
        $access_token->setResourceOwnerPublicId($jwt->getClaim('resource_owner'));

        if ($jwt->hasClaim('exp')) {
            $access_token->setExpiresAt($jwt->getClaim('exp'));
        }
        if ($jwt->hasClaim('other')) {
            $access_token->setParameters($jwt->getClaim('other'));
        }
        if ($jwt->hasClaim('cnf')) {
            $access_token->setParameter('cnf', $jwt->getClaim('cnf'));
        }
        if ($jwt->hasClaim('scp')) {
            $access_token->setScope($jwt->getClaim('scp'));
        }
        if ($jwt->hasClaim('refresh_token')) {
            $access_token->setRefreshToken($jwt->getClaim('refresh_token'));
        }
        if ($jwt->hasClaim('metadatas')) {
            $access_token->setMetadatas($jwt->getClaim('metadatas'));
        }

        return $access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken(AccessTokenInterface $access_token)
    {
        //Not implemented
    }

    /**
     * {@inheritdoc}
     */
    protected function saveAccessToken(AccessTokenInterface $access_token)
    {
        // Nothing to do.
    }

    /**
     * @return bool
     */
    private function isEncryptionEnabled()
    {
        return null !== $this->key_encryption_algorithm && null !== $this->content_encryption_algorithm && null !== $this->key_encryption_key;
    }
}
