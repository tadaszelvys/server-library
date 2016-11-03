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
use Jose\JWTCreatorInterface;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Behaviour\HasIssuer;
use OAuth2\Behaviour\HasJWTCreator;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

class JWTAccessTokenManager extends AccessTokenManager
{
    use HasJWTLoader;
    use HasJWTCreator;
    use HasIssuer;

    /**
     * @var string
     */
    private $signature_algorithm;

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $signature_key_set;

    /**
     * @var string
     */
    private $key_encryption_algorithm;

    /**
     * @var string
     */
    private $content_encryption_algorithm;

    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $key_encryption_key_set;

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \Jose\JWTCreatorInterface    $jwt_creator
     * @param \Jose\JWTLoaderInterface     $jwt_loader
     * @param string                       $signature_algorithm
     * @param \Jose\Object\JWKSetInterface $signature_key_set
     * @param string                       $issuer
     * @param string                       $key_encryption_algorithm
     * @param string                       $content_encryption_algorithm
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function __construct(JWTCreatorInterface $jwt_creator, JWTLoaderInterface $jwt_loader, $signature_algorithm, JWKSetInterface $signature_key_set, $key_encryption_algorithm, $content_encryption_algorithm, JWKSetInterface $key_encryption_key_set, $issuer)
    {
        Assertion::string($signature_algorithm);
        Assertion::string($key_encryption_algorithm);
        Assertion::string($content_encryption_algorithm);
        Assertion::greaterThan($signature_key_set->countKeys(), 0, 'The signature key set must have at least one key.');
        Assertion::greaterThan($key_encryption_key_set->countKeys(), 0, 'The encryption key set must have at least one key.');
        Assertion::inArray($signature_algorithm, $jwt_creator->getSupportedSignatureAlgorithms());
        Assertion::inArray($key_encryption_algorithm, $jwt_creator->getSupportedKeyEncryptionAlgorithms());
        Assertion::inArray($content_encryption_algorithm, $jwt_creator->getSupportedContentEncryptionAlgorithms());

        $this->signature_algorithm = $signature_algorithm;
        $this->key_encryption_algorithm = $key_encryption_algorithm;
        $this->content_encryption_algorithm = $content_encryption_algorithm;
        $this->setIssuer($issuer);
        $this->signature_key_set = $signature_key_set;
        $this->key_encryption_key_set = $key_encryption_key_set;

        $this->setJWTCreator($jwt_creator);
        $this->setJWTLoader($jwt_loader);
    }

    /**
     * {@inheritdoc}
     */
    public function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null, ClientInterface $resource_server = null)
    {
        $payload = $this->preparePayload($access_token, $resource_server);
        $signature_header = $this->prepareSignatureHeader();
        $signature_key = $this->signature_key_set->getKey(0);
        Assertion::notNull($signature_key, 'Unable to find a key to sign the Access Token. Please verify the selected key set contains suitable keys.');
        $encryption_key = $this->key_encryption_key_set->getKey(0);
        Assertion::notNull($signature_key, 'Unable to find a key to encrypt the Access Token. Please verify the selected key set contains suitable keys.');
        $jwt = $this->getJWTCreator()->sign($payload, $signature_header, $signature_key);

        $encryption_header = $this->prepareEncryptionHeader($client, $resource_server);
        $recipient_key = $encryption_key;
        $jwt = $this->getJWTCreator()->encrypt($jwt, $encryption_header, $recipient_key);

        $access_token->setToken($jwt);
    }

    /**
     * @param \OAuth2\Client\ClientInterface      $client
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
                'iss' => $this->getIssuer(),
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
        $header['aud'] = null === $resource_server ? $this->getIssuer() : $resource_server->getPublicId();

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
        $aud = [$this->getIssuer()];
        if (null !== $resource_server) {
            $access_token[] = $resource_server->getPublicId();
        }
        $payload = [
            'jti'            => Base64Url::encode(random_bytes(25)),
            'iss'            => $this->getIssuer(),
            'aud'            => $aud,
            'iat'            => time(),
            'nbf'            => time(),
            'exp'            => $access_token->getExpiresAt(),
            'sub'            => $access_token->getClientPublicId(),
            'token_type'     => $access_token->getTokenType(),
            'scp'            => $access_token->getScope(),
            'resource_owner' => $access_token->getResourceOwnerPublicId(),
            'user_account'   => $access_token->getUserAccountPublicId(),
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
            $jwt = $this->getJWTLoader()->load($assertion, $this->key_encryption_key_set, true);
            $this->jwt_loader->verify($jwt, $this->signature_key_set);
        } catch (\Exception $e) {
            return;
        }

        $access_token = new JWTAccessToken();
        $access_token->setToken($assertion);
        $access_token->setJWS($jwt);
        $access_token->setClientPublicId($jwt->getClaim('sub'));
        $access_token->setTokenType($jwt->getClaim('token_type'));
        $access_token->setResourceOwnerPublicId($jwt->getClaim('resource_owner'));
        $access_token->setUserAccountPublicId($jwt->getClaim('user_account'));

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
}
