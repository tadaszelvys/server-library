<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\JWTCreator;
use Jose\Object\JWKInterface;
use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTCreator;
use OAuth2\Behaviour\HasUserManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\User\UserManagerInterface;

final class UserInfoEndpoint implements UserInfoEndpointInterface
{
    use HasExceptionManager;
    use HasUserManager;
    use HasClientManager;
    use HasUserinfo;
    use HasJWTCreator;

    /**
     * @var string|null
     */
    private $issuer = null;

    /**
     * @var \Jose\Object\JWKInterface|null
     */
    private $signature_key = null;

    /**
     * @var string|null
     */
    private $signature_algorithm = null;

    /**
     * UserInfoEndpoint constructor.
     *
     * @param \OAuth2\User\UserManagerInterface           $user_manager
     * @param \OAuth2\Client\ClientManagerInterface       $client_manager
     * @param \OAuth2\OpenIdConnect\UserInfoInterface     $userinfo
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(UserManagerInterface $user_manager,
                                ClientManagerInterface $client_manager,
                                UserInfoInterface $userinfo,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->setUserManager($user_manager);
        $this->setClientManager($client_manager);
        $this->setUserinfo($userinfo);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param \Jose\JWTCreator          $jwt_creator
     * @param string                    $issuer
     * @param string                    $signature_algorithm
     * @param \Jose\Object\JWKInterface $signature_key
     */
    public function enableSignedResponsesSupport(JWTCreator $jwt_creator,
                                                 $issuer,
                                                 $signature_algorithm,
                                                 JWKInterface $signature_key
    ) {
        Assertion::string($issuer);
        Assertion::inArray($signature_algorithm, $jwt_creator->getSupportedSignatureAlgorithms());
        $this->setJWTCreator($jwt_creator);

        $this->issuer = $issuer;
        $this->signature_key = $signature_key;
        $this->signature_algorithm = $signature_algorithm;
    }

    /**
     * @return bool
     */
    public function isSignedResponsesSupportEnabled()
    {
        return null !== $this->getJWTCreator();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms()
    {
        $jwt_creator = $this->getJWTCreator();

        return null === $jwt_creator ? [] : $jwt_creator->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        $jwt_creator = $this->getJWTCreator();

        return null === $jwt_creator ? [] : $jwt_creator->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        $jwt_creator = $this->getJWTCreator();

        return null === $jwt_creator ? [] : $jwt_creator->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function handle(AccessTokenInterface $access_token)
    {
        $this->checkScope($access_token->getScope());
        $this->checkHasRedirectUri($access_token);

        $client = $this->getClient($access_token);
        $user = $this->getUser($access_token);
        $endpoint_claims = $this->getEndpointClaims($access_token);

        $claims = $this->getUserinfo()->getUserinfo(
            $client,
            $user,
            $access_token->getMetadata('redirect_uri'),
            $access_token->hasMetadata('claims_locales') ? $access_token->getMetadata('claims_locales') : [],
            $endpoint_claims,
            $access_token->getScope()
        );

        if (true === $this->isSignedResponsesSupportEnabled()) {
            $claims = array_merge(
                $claims,
                [
                    'jti'       => Base64Url::encode(random_bytes(25)),
                    'iss'       => $this->issuer,
                    'aud'       => $client->getPublicId(),
                    'iat'       => time(),
                    'nbf'       => time(),
                    'exp'       => $access_token->getExpiresAt(),
                ]
            );

            return $this->signAndEncrypt($claims, $client);
        }

        return $claims;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     *
     * @return array
     */
    private function getEndpointClaims(AccessTokenInterface $access_token)
    {
        if (!$access_token->hasMetadata('requested_claims')) {
            return [];
        }
        
        $requested_claims = $access_token->getMetadata('requested_claims');
        if (true === array_key_exists('userinfo', $requested_claims)) {
            return $requested_claims['userinfo'];
        }
        
        return [];
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface
     */
    private function getClient(AccessTokenInterface $access_token)
    {
        $client = $this->getClientManager()->getClient($access_token->getClientPublicId());
        if (null === $client) {
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'Unable to find the client.'
            );
        }

        return $client;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return null|\OAuth2\User\UserInterface
     */
    private function getUser(AccessTokenInterface $access_token)
    {
        $user = $this->getUserManager()->getUser($access_token->getResourceOwnerPublicId());
        if (null === $user) {
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'Unable to find the resource owner.'
            );
        }

        return $user;
    }

    /**
     * @param array                          $claims
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return string
     */
    private function signAndEncrypt($claims, ClientInterface $client)
    {
        $jwt = $this->getJWTCreator()->sign(
            $claims,
            [
                'typ' => 'JWT',
                'alg' => $this->signature_algorithm,
            ],
            $this->signature_key
        );

        if ($client->hasPublicKeySet() && $client->has('id_token_encrypted_response_alg') && $client->has('id_token_encrypted_response_enc')) {
            $key_set = $client->getPublicKeySet();
            $key = $key_set->selectKey('enc');
            if (null !== $key) {
                $jwt = $this->getJWTCreator()->encrypt(
                    $jwt,
                    [
                        'alg' => $client->get('id_token_encrypted_response_alg'),
                        'enc' => $client->get('id_token_encrypted_response_enc'),
                    ],
                    $key
                );
            }
        }

        return $jwt;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkHasRedirectUri(AccessTokenInterface $access_token)
    {
        if (!$access_token->hasMetadata('redirect_uri')) {
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'The access token has no "redirect_uri" data and cannot be used.'
            );
        }
    }

    /**
     * @param string[] $scope
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkScope(array $scope)
    {
        if (!in_array('openid', $scope)) {
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'The access token does not contain the "openid" scope.'
            );
        }
    }
}
